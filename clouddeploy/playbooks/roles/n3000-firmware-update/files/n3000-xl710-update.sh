#!/bin/bash -e

nvmupdate_dir="/usr/share/opae/bin"

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

function check_driver() {
    info "Making sure N3000 network I/O port's driver is loaded..."
    for address in $(lspci -Dd 8086:0d58 | awk '{print $1}'); do
        if [[ -e /sys/bus/pci/drivers/i40e/${address} ]]; then
            continue
        fi
        if ! echo "$address" | tee /sys/bus/pci/drivers/i40e/bind > /dev/null || \
                ! udevadm settle; then
            error "Failed to make sure N3000 network I/O port's driver is loaded"
            exit 1
        fi
    done
    info "Successfully made sure N3000 network I/O port's driver is loaded"
}

function pre_check() {
    expected_version=$(awk 'match($0,/^EEPID: ([0-9A-Fa-f]+)/,ver) {print tolower(ver[1])}' ${xl710_config_file})
    if [[ ${expected_version} == "" ]]; then
        error "Unable to determine expected version from XL710 config file, aborting!!!"
        exit 1
    fi
    need_update=0
    for address in $(lspci -Dd 8086:0d58 | awk '{print $1}'); do
        if [[ -e /sys/bus/pci/drivers/i40e/${address} ]]; then
            dev_name=$(basename /sys/bus/pci/drivers/i40e/${address}/net/*)
            info "N3000 network I/O port ${dev_name} output before update:"
            ethtool -i ${dev_name}
            if ! ethtool -i ${dev_name} | grep -E "firmware-version: .* 0x${expected_version} " > /dev/null; then
                info "Update needed for ${dev_name}"
                need_update=1
            fi
        fi
    done
    return ${need_update}
}

function install_package_and_copy_files() {
    info "Installing necessary package..."
    if ! yum clean all || ! yum install -y intel-nvmupdate; then
        error "Failed to install necessary package, aborting!!!"
        exit 1
    fi
    info "Successfully installed necessary package"

    info "Copying files to nvmupdate directory..."
    if ! cp ${xl710_image_file} ${nvmupdate_dir}/ || \
            ! cp ${xl710_config_file} ${nvmupdate_dir}/; then
        error "Failed to copy files to nvmupdate directory, aborting!!!"
        exit 1
    fi
    info "Successfully copied files to nvmupdate directory"
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

function remove_vfs() {
    info "Removing N3000 network I/O VFs..."
    for address in $(lspci -Dd 8086:0d58 | awk '{print $1}'); do
        if ! echo 0 > /sys/bus/pci/drivers/i40e/${address}/sriov_numvfs; then
            error "Failed to remove N3000 network I/O VFs, aborting!!!"
            exit 1
        fi
    done
    info "Successfully removed N3000 network I/O VFs"
}

function update_firmware() {
    # Try up to 3 times due to RT kernel which cause nvmupdate64e to report
    # wrong update status
    info "Updating N3000's XL710 firmware..."
    sucess=0
    max_try=3
    retry_sleep=60
    cd ${nvmupdate_dir}
    for i in $(seq 1 ${max_try}); do
        update_cmd="chrt -f 50 ./nvmupdate64e -c $(basename ${xl710_config_file}) -u -l /dev/stdout"
        if [[ ${i} -eq 1 ]]; then
            # Backup existing firmware on first update attempt, in case
            # rollback is needed
            update_cmd+=" -b"
        fi
        if ${update_cmd}; then
            sucess=1
            break
        fi
        info "Update attempt #${i} failed"
        if [[ ${i} -lt ${max_try} ]]; then
            info "Sleep ${retry_sleep} seconds before trying again"
            sleep ${retry_sleep}
        fi
    done
    if [[ ${sucess} -ne 1 ]]; then
        error "Failed to update N3000's XL710 firmware, aborting!!!"
        exit 1
    fi
    info "Sucessfully updated N3000's XL710 firmware"
}

function usage() {
    echo "Usage: $(basename "$0") -c <XL710 config file> -f <XL710 image file> [-u]"
    echo "  -c  <XL710 config file>  i.e. nvmupdate_25G_0D58.cfg"
    echo "  -f  <XL710 image file>   i.e. PSG_XL710_7p00_CFGID2p61_XLAUI_DID_0D58_K32246_800052B0.bin"
    echo "  -u  perform XL710 update"
    echo "  -y  assumed yes, skip prompt"
    echo "  -h  display this help messsage"
    exit 1
}

while getopts ":c:f:uyh" opt; do
    case ${opt} in
        c)
            if [[ ! -e ${OPTARG} ]]; then
                echo "XL710 config file '${OPTARG}' not found"
                exit 1
            fi
            xl710_config_file=${OPTARG}
            ;;
        f)
            if [[ ! -e ${OPTARG} ]]; then
                echo "XL710 image file '${OPTARG}' not found"
                exit 1
            fi
            xl710_image_file=${OPTARG}
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

if [[ $(lspci -d 8086:0b30 | wc -l) -eq 0 ]]; then
    echo "No N3000 card found, exiting"
    exit 0
fi
if [[ -z ${xl710_config_file} || -z ${xl710_image_file} ]]; then
    echo "Missing XL710 config file and/or XL710 image file options"
    exit 1
fi

info "Starting N3000 XL710 update script..."
info "XL710 config file: ${xl710_config_file}"
info "XL710 image file: ${xl710_image_file}"
check_driver
if pre_check; then
    info "N3000's XL710 firmware already running with desired version"
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
    install_package_and_copy_files
    stop_services
    # prevent interruption during update
    trap '' SIGINT SIGTERM SIGTSTP
    SECONDS=0
    remove_vfs
    update_firmware
    duration=$SECONDS
    info "$(($duration / 60)) minutes and $(($duration % 60)) seconds elapsed"
    info "Update ran successfully, please reboot server for changes to take in effect"
    exit 2
else
    info "To perform update, please add -u option to command line"
    exit 3
fi
