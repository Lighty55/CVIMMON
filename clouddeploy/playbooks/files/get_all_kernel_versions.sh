#!/bin/sh

# NOTE: This will only return either kernel or kernel-rt but not both.
#       Technically having both type installed at the same time is not
#       possible by CVIM installer.
for k in kernel kernel-rt; do
    if rpm -q $k >/dev/null 2>&1; then
        rpm -q --qf="%{VERSION}-%{RELEASE}.%{ARCH}\n" $k
        break
    fi
done
