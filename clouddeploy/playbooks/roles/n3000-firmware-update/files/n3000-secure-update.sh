#!/bin/bash -e

max10_json="/usr/share/opae/n3000/one-time-update/25G/super-rsu.json"
otsu_json="/usr/share/opae/n3000/one-time-update/25G/otsu-25G.json"
super_rsu_json="/usr/share/opae/n3000/super-rsu/2x2x25G/super-rsu-2x2x25G.json"
n3000="8086:0b30"

function timestamp() {
    echo "$(date +"%Y-%m-%d %H:%M:%S")"
}

function info() {
    #echo -e "\e[1;32m$(timestamp) INFO: $@\e[0m"
    echo "$(timestamp) INFO: $@"
}

function error() {
    #echo -e "\e[1;31m$(timestamp) ERROR: $@\e[0m"
    echo "$(timestamp) ERROR: $@"
}

function pre_check() {
    info "Checking if secure update is require..."
    if ! yum clean all > /dev/null ||
            ! yum install -y opae-intel-fpga-driver opae-tools > /dev/null; then
        error "Failed to install necessary packages, aborting!!!"
        exit 1
    fi
    #Board Management Controller, MAX10 NIOS FW version D.2.0.19
    #Board Management Controller, MAX10 Build version D.2.0.6
    #//****** FME ******//
    #Object Id                     : 0xEE00000
    #PCIe s:b:d.f                  : 0000:1a:00.0
    #Device Id                     : 0x0b30
    #Numa Node                     : 0
    #Ports Num                     : 01
    #Bitstream Id                  : 0x2392920A010501
    #Bitstream Version             : 0.2.3
    #Pr Interface Id               : cf9b1c50-37c9-45e9-8030-f921b17d2b3a
    #Boot Page                     : user
    info "N3000 FME output before secure update:"
    fpgainfo fme
    fme_output=$(fpgainfo fme)
    if ! grep -w "MAX10 NIOS FW version D.2" <<< ${fme_output} > /dev/null || \
            ! grep -w "MAX10 Build version D.2" <<< ${fme_output}> /dev/null; then
        info "MAX10 one-time-secure-update require"
        return 1
    fi
    tmp_bitstream_id=$(printf "0x%X" ${user_image_bitstream_id})
    if ! grep -E "Bitstream Id\s+:\s+${tmp_bitstream_id}\s" <<< ${fme_output} > /dev/null; then
        info "User image update require"
        return 1
    fi
    return 0
}

function install_packages() {
    info "Remove any existing N3000 firmware packages..."
    # Packages from version 1.0: opae-super-rsu-n3000*
    #                            opae-super-rsu-n3000-data*
    # Packages from version 1.1: opae-one-time-update-n3000-25G*
    #                            opae-super-rsu-n3000-2x2x25G*
    if ! yum remove -y opae-super-rsu-n3000* \
                       opae-super-rsu-n3000-data* \
                       opae-one-time-update-n3000-25G* \
                       opae-super-rsu-n3000-2x2x25G*; then
        error "Failed to remove any existing N3000 firmware packages, aborting!!!"
        exit 1
    fi
    info "Successfully removed any existing N3000 firmware packages"

    # Locking to use specific firmware packages from version 1.1 to avoid json
    # file patching error: opae-one-time-update-n3000-25G-1.3.6-6
    #                      opae-super-rsu-n3000-2x2x25G-1.3.6-6
    packages="opae-one-time-update-n3000-25G-1.3.6-6 \
              opae-super-rsu-n3000-2x2x25G-1.3.6-6 \
              opae.admin \
              python-intelhex \
              vc-fpga-utils"
    info "Installing all necessary packages..."
    if ! yum install -y ${packages}; then
        error "Failed to install all necessary packages, aborting!!!"
        exit 1
    fi
    info "Successfully installed all necesary packages"
}

function patch_jsons() {
    info "Copying user image to one-time-secure-update directory..."
    if ! cp ${user_image_file} $(dirname ${otsu_json}); then
        error "Failed to copy user image to one-time-secure-update directory, aborting!!!"
        exit 1
    fi
    info "Successfully copied user image to one-time-secure-update directory"

    info "Copying user image to super-rsu directory..."
    if ! cp ${user_image_file} $(dirname ${super_rsu_json}); then
        error "Failed to copy user image to super-rsu directory, aborting!!!"
        exit 1
    fi
    info "Successfully copied user image to super-rsu directory"

    base_file=$(basename ${user_image_file})

    info "Patching one-time-secure-update json file with user image info..."
    sed -i.org "s/vista_rot_factory_4x25G_reverse.bin/${base_file}/g;
                /${base_file}/a\            \"seek\": \"0x00000400\"," ${otsu_json}
    if ! grep "${base_file}" ${otsu_json} > /dev/null || \
            ! grep -E '^\s+"seek": "0x00000400",$' ${otsu_json} > /dev/null; then
        error "Failed to patch one-time-secure-update json file with user image info"
        exit 1
    fi
    info "Successfully patched one-time-secure-update json file with user image info"

    info "Patching super-rsu json file with user image info..."
    sed -i.org "s/\"enabled\": false/\"enabled\": true/g
                s/sr_vista_rot_2x2x25g_19ww43.6_unsigned.bin/${base_file}/g
                s/0x0023000410010309/${user_image_bitstream_id}/g" ${super_rsu_json}
    if grep '"enabled": false' ${super_rsu_json} > /dev/null || \
            ! grep "${base_file}" ${super_rsu_json} > /dev/null || \
            ! grep "${user_image_bitstream_id}" ${super_rsu_json} > /dev/null; then
        error "Failed to patch super-rsu json file with user image info"
        exit 1
    fi
    info "Successfully patched super-rsu json file with user image info"
}

function stop_services() {
    info "Stopping any services that interact with N3000"
    info "Stopping all Nova services..."
    if systemctl stop docker-nova*; then
        info "Successfully stopped all Nova services"
    else
        error "Failed to stop all Nova services"
    fi
    info "Stopping all Neutron services..."
    if systemctl stop docker-neutron*; then
        info "Successfully stopped all Neutron services"
    else
        error "Failed to stop all Neutron services"
    fi
    info "Stopping Telegraf service..."
    if systemctl stop telegraf; then
        info "Successfully stopped Telegraf service"
    else
        error "Failed to stop Telegraf service"
    fi
}

function unbind_remove_vfs() {
    info "Unbinding i40e driver on all N3000 network I/O ports..."
    for address in $(lspci -Dd 8086:0d58 | awk '{print $1}'); do
        if [[ -e /sys/bus/pci/drivers/i40e/${address} ]]; then
            if ! echo "$address" > /sys/bus/pci/drivers/i40e/unbind; then
                error "Failed to unbind i40e driver, aborting!!!"
                exit 1
            fi
        fi
    done
    info "Successfully unbind i40e driver on all N3000 network I/O ports"

    info "Removing any existing N3000 FPGA VFs..."
    if [[ $(lspci -d 1172:5050 | wc -l) -gt 0 ]]; then
        if ! /opt/cisco/bbdev_pf_config_app/remove-fpga-vf.sh; then
            error "Failed to remove N3000 FPGA VFs, aborting!!!"
            exit 1
        fi
        info "Successfully removed any existing FPGA VFs"
    else
        info "No N3000 FPGA VF found, skipping"
    fi
}

function update_max10() {
    cards=$(lspci -d ${n3000} | wc -l)
    if [[ $(fpgainfo fme | grep -w "MAX10 Build version D.1" | wc -l) -gt 0 ]]; then
        info "Updating MAX10 to temporary image..."
        if ! chrt -f 80 super-rsu ${max10_json} --with-rsu --log-level debug; then
            fpgainfo fme
            error "Failed to update MAX10 to temporary image, aborting!!!"
            error "Before re-trying, please power off server and wait few minutes then power server back on"
            exit 1
        fi
        info "Successfully updated MAX10 to temporary image"
    elif [[ $(fpgainfo fme | grep -w "MAX10 Build version D.111.2.13" | wc -l) -eq ${cards} ]]; then
        info "MAX10 already updated to temporary image, skipping"
    elif [[ $(fpgainfo fme | grep -w "MAX10 Build version D.2" | wc -l) -eq ${cards} ]]; then
        info "MAX10 already updated to secure image, skipping"
    else
        error "Failed to determine MAX10 temporary image state on one or more card, aborting"
        error "Before re-trying, please power off server and wait few minutes then power server back on"
        exit 1
    fi
}

function perform_otsu() {
    cards=$(lspci -d ${n3000} | wc -l)
    if [[ $(fpgainfo fme | grep -w "MAX10 Build version D.111.2.13" | wc -l) -eq ${cards} ]]; then
        info "Performing one-time-secure-update..."
        if ! chrt -f 80 fpgaotsu ${otsu_json} --rsu --log-level debug; then
            fpgainfo fme
            error "Failed to perform one-time-secure-update, aborting..."
            exit 1
        fi
    elif [[ $(fpgainfo fme | grep -w "MAX10 Build version D.2" | wc -l) -eq ${cards} ]]; then
        info "Potential partitially updated one-time-secure-update state found, resuming update..."
        if ! chrt -f 80 super-rsu ${super_rsu_json} --with-rsu --log-level debug; then
            fpgainfo fme
            error "Failed to resume one-time-secure-update, aborting..."
            exit 1
        fi
    fi
    info "Successfully performed one-time-secure-update"
}

function usage() {
    echo "Usage: $(basename "$0") -b <user image bitstream id> -f <unsigned user image file> [-u]"
    echo "  -b  <user image's bitsteam id>  i.e. 0x2392920A010501"
    echo "  -f  <unsigned user image file>  i.e. phase1_turbo4g_2x1x25g_1fvl_raw_20ww02_unsigned.bin"
    echo "  -u  perform secure and user image update"
    echo "  -y  assumed yes, skip prompt"
    echo "  -h  display this help messsage"
    exit 1
}

while getopts ":b:f:uyh" opt; do
    case ${opt} in
        b)
            if [[ ! ${OPTARG} == "0x"* || ${#OPTARG} -gt 18 ]]; then
                echo "Incorrect user image bitstream id, should start with 0x and max of 18 characters long"
                exit 1
            fi
            user_image_bitstream_id=$(printf "0x%016x" ${OPTARG})
            ;;
        f)
            if [[ ! -e ${OPTARG} ]]; then
                echo "Unsigned user image '${OPTARG}' not found"
                exit 1
            fi
            user_image_file=${OPTARG}
            ;;
        u)
            perform_update=true
            ;;
        y)
            assumed_yes=true
            ;;
        h|*)
            usage
            ;;
    esac
done

if [[ $(lspci -d ${n3000} | wc -l) -eq 0 ]]; then
    echo "No N3000 card found, exiting"
    exit 0
fi
if [[ -z ${user_image_file} || -z ${user_image_bitstream_id} ]]; then
    echo "Missing unsigned user image file and/or user image bitstream id options"
    exit 1
fi

info "Starting N3000 secure update script..."
info "Unsigned user image file: ${user_image_file}"
info "User image bitstream id: ${user_image_bitstream_id}"
if pre_check; then
    info "N3000 already in secure mode with desired user image"
    info "No update needed, exiting"
    exit 0
elif [[ ${perform_update} == "true" ]]; then
    if [[ ${assumed_yes} != "true" ]]; then
        while [[ ${cont_prompt} != "yes" ]]; do
            echo "Performing update will disrupte the server's operation"
            echo "Any Nova, Neutron, and Telegraf services will be stopped!!!"
            read -p "Would you like to continue <yes>: " cont_prompt
        done
    fi
    install_packages
    patch_jsons

    stop_services
    # prevent interruption during update
    trap '' SIGINT SIGTERM SIGTSTP
    SECONDS=0

    unbind_remove_vfs
    update_max10

    unbind_remove_vfs
    perform_otsu

    duration=$SECONDS
    info "$(($duration / 60)) minutes and $(($duration % 60)) seconds elapsed"

    info "N3000 FME output after secure update:"
    fpgainfo fme

    unbind_remove_vfs
    info "Update ran successfully, please reboot server for changes to take in effect"
    exit 2
else
    info "To perform update, please add -u option to command line"
    exit 3
fi
