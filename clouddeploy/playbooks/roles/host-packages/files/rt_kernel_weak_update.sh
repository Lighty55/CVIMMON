#!/bin/bash

# Only handle modules built by CVIM
modules=( $(ls -d /lib/modules/*/extra/*-cvim 2> /dev/null) )
if [ ${#modules[@]} -eq 0 ]; then
    echo "No module build by CVIM found, exiting ..."
    exit 0
fi
if [ $(basename -a ${modules[@]} | sort | uniq -d | wc -l) -gt 0 ]; then
    echo "ERROR: Multiple version of same module found, aborting ..."
    exit 1
fi
kernel_type=kernel-rt
kernels=( $(rpm -q --qf="%{VERSION}-%{RELEASE}.%{ARCH}\n" ${kernel_type}) )
if [ $? -ne 0 ]; then
    echo "No ${kernel_type} found, exiting ..."
    exit 0
fi

set -e
for kernel in ${kernels[@]}; do
    echo "Installed ${kernel_type} version ${kernel} found"
    symvers_file="/boot/symvers-${kernel}.gz"
    if [ -e ${symvers_file} ]; then
        echo "${symvers_file} found, weak-updates is not needed, skipping"
        continue
    fi
    weak_path=/lib/modules/${kernel}/weak-updates
    if [ ! -d ${weak_path} ]; then
        echo "No weak-updates path found for ${kernel}, skipping"
        continue
    fi
    for module in ${modules[@]}; do
        if grep -w ${kernel} <<< ${module} > /dev/null; then
            echo "No weak-updates needed for ${module}, same version, skipping"
            continue
        fi
        weak_module="${weak_path}/${module##*/}"
        if [ -d ${weak_module} ]; then
            # In case of driver update, blindly remove existing so it will
            # always point to the intended version.
            echo "Symlink already exist for ${module} at ${weak_path}, removing"
            rm -rf ${weak_module}
        fi
        echo "Creating symlink for ${module} to ${weak_path}"
        cp -as ${module} ${weak_path}
    done
    echo "Updating depmod for ${kernel}"
    depmod -aeF "/boot/System.map-${kernel}" "${kernel}" > /dev/null
    if lsmod | grep -w ^i40e > /dev/null; then
        initramfs_img="/boot/initramfs-${kernel}.img"
        echo "Updating ${initramfs_img}"
        dracut -f "${initramfs_img}" "${kernel}" > /dev/null
    fi
done
