#!/bin/sh

if [[ $# -ne 2 ]]; then
    echo "Incorrect usage: $0 <SCELNX_64 utility file location> <product name input>"
    exit 1
fi

scelnx_util=$1
if [[ ${scelnx_util} == "" ]]; then
    echo "Missing SCELNX_64 utility file location"
    exit 2
elif [[ ! -f ${scelnx_util} ]]; then
    echo "${scelnx_util} utility not found"
    exit 2
fi

product_name=$2
if [[ ${product_name} == "" ]]; then
    echo "Missing product name input"
    exit 3
elif ! dmidecode -t 1 | grep -Ew "Product Name:\s+${product_name}"; then
    echo "Mismatching product name ${product_name}"
    exit 3
fi

# ./SCELNX_64 /a /o /s bios.txt /lang [/ndef]
reboot_flag=0

# SpeedStep (Pstates)
if ${scelnx_util} /o /ms PMS001 | grep -Ew '\*\[.*\]Enable' > /dev/null 2>&1; then
    echo '"SpeedStep (Pstates)" already set to Enable'
else
    echo -n '"SpeedStep (Pstates)" change to Enable: '
    if ${scelnx_util} /i /ms PMS001 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# Config TDP (hidden option)
if ${scelnx_util} /o /ms PMSOEM002 | grep -Ew '\*\[.*\]Level 2' > /dev/null 2>&1; then
    echo '"Config TDP" already set to Level 2'
else
    echo -n '"Config TDP" change to Level 2: '
    if ${scelnx_util} /i /ms PMSOEM002 /qv 02 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# Turbo Mode
if ${scelnx_util} /o /ms PMS002 | grep -Ew '\*\[.*\]Enable' > /dev/null 2>&1; then
    echo '"Turbo Mode" already set to Enable'
else
    echo -n '"Turbo Mode" change to Enable: '
    if ${scelnx_util} /i /ms PMS002 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null1; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi
# Energy Efficient Turbo (hidden option)
if ${scelnx_util} /o /ms PMSOEM003 | grep -Ew '\*\[.*\]Disable' > /dev/null 2>&1; then
    echo '"Energy Efficient Turbo" already set to Disable'
else
    echo -n '"Energy Efficient Turbo" change to Disable: '
    if ${scelnx_util} /i /ms PMSOEM003 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# Uncore Freq Scaling (UFS) (hidden option)
if ${scelnx_util} /o /ms PMSOEM001 | grep -Ew '\*\[.*\]Disable' > /dev/null 2>&1; then
    echo '"Uncore Freq Scaling (UFS)" already set to Disable'
else
    echo -n '"Uncore Freq Scaling (UFS)" change to Disable: '
    if ${scelnx_util} /i /ms PMSOEM001 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# Hardware P-States
if ${scelnx_util} /o /ms PMS003 | grep -Ew '\*\[.*\]Disable' > /dev/null 2>&1; then
    echo '"Hardware P-States" already set to Disable'
else
    echo -n '"Hardware P-States" change to Disable: '
    if ${scelnx_util} /i /ms PMS003 /qv 00 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# EPP Enable (hidden option)
if ${scelnx_util} /o /ms PMSOEM009 | grep -Ew '\*\[.*\]Disable' > /dev/null 2>&1; then
    echo '"EPP Enable" already set to Disable'
else
    echo -n '"EPP Enable" change to Disable: '
    if ${scelnx_util} /i /ms PMSOEM009 /qv 00 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# Package C State
if ${scelnx_util} /o /ms PMS007 | grep -Ew '\*\[.*\]C0/C1 state' > /dev/null 2>&1; then
    echo '"Package C State" already set to C0/C1 state'
else
    echo -n '"Package C State" change to C0/C1 state: '
    if ${scelnx_util} /i /ms PMS007 /qv 00 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# Link Speed Mode (hidden option)
if ${scelnx_util} /o /ms KTSV001 | grep -Ew '\*\[.*\]Fast' > /dev/null 2>&1; then
    echo '"Link Speed Mode" already set to Fast'
else
    echo -n '"Link Speed Mode" change to Fast: '
    if ${scelnx_util} /i /ms KTSV001 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# Link Frequency Select (hidden option)
if ${scelnx_util} /o /ms KTIS001 | grep -Ew '\*\[.*\]Auto' > /dev/null 2>&1; then
    echo '"Link Frequency Select" already set to Auto'
else
    echo -n '"Link Frequency Select" change to Auto: '
    if ${scelnx_util} /i /ms KTIS001 /qv 02 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# Hardware Prefetcher | MLC Streamer Prefetcher (MSR 1A4h Bit[0])
if ${scelnx_util} /o /ms PRSS016 | grep -Ew '\*\[.*\]Enable' > /dev/null 2>&1; then
    echo '"Hardware Prefetcher" already set to Enable'
else
    echo -n '"Hardware Prefetcher" change to Enable: '
    if ${scelnx_util} /i /ms PRSS016 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# Adjacent Cache Prefetch | MLC Spatial Prefetcher (MSR 1A4h Bit[1])
if ${scelnx_util} /o /ms PRSS017 | grep -Ew '\*\[.*\]Enable' > /dev/null 2>&1; then
    echo '"Adjacent Cache Prefetch" already set to Enable'
else
    echo -n '"Adjacent Cache Prefetch" change to Enable: '
    if ${scelnx_util} /i /ms PRSS017 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# DCU Streamer Prefetcher | DCU streamer prefetcher is an L1 data cache prefetcher (MSR 1A4h [2])
if ${scelnx_util} /o /ms PRSS018 | grep -Ew '\*\[.*\]Enable' > /dev/null 2>&1; then
    echo '"DCU Streamer Prefetcher" already set to Enable'
else
    echo -n '"DCU Streamer Prefetcher" change to Enable: '
    if ${scelnx_util} /i /ms PRSS018 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# DCU IP Prefetcher | DCU IP prefetcher is an L1 data cache prefetcher (MSR 1A4h [3])
if ${scelnx_util} /o /ms PRSS019 | grep -Ew '\*\[.*\]Enable' > /dev/null 2>&1; then
    echo '"DCU IP Prefetcher" already set to Enable'
else
    echo -n '"DCU IP Prefetcher" change to Enable: '
    if ${scelnx_util} /i /ms PRSS019 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# LLC Prefetch
if ${scelnx_util} /o /ms PRSS01A | grep -Ew '\*\[.*\]Enable' > /dev/null 2>&1; then
    echo '"LLC Prefetch" already set to Enable'
else
    echo -n '"LLC Prefetch" change to Enable: '
    if ${scelnx_util} /i /ms PRSS01A /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# Performance P-limit | Perf P Limit (hidden option)
if ${scelnx_util} /o /ms PMSOEM007 | grep -Ew '\*\[.*\]Enable' > /dev/null 2>&1; then
    echo '"Perf P Limit" already set to Enable'
else
    echo -n '"Perf P Limit" change to Enable: '
    if ${scelnx_util} /i /ms PMSOEM007 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# NUMA Optimized | Numa
if ${scelnx_util} /o /ms CRCS005 | grep -Ew '\*\[.*\]Enable' > /dev/null 2>&1; then
    echo '"Numa" already set to Enable'
else
    echo -n '"Numa" change to Enable: '
    if ${scelnx_util} /i /ms CRCS005 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# NOTE: Skip disabling since there is no Map String to this particular Setup
#       Question; therefore, cannot set via the tool.
#       The default value is already Disable, so it should be fine.
# Sub_NUMA Cluster | SNC (hidden option)
#if ${scelnx_util} /o /ms ?????? | grep -Ew '\*\[.*\]Disable' > /dev/null 2>&1; then
#    echo '"Numa" already set to Disable'
#else
#    echo -n '"Numa" change to Disable: '
#    if ${scelnx_util} /i /ms ?????? /qv 00 2>&1 | grep 'Question value imported successfully' > /dev/null; then
#        echo 'Success'
#        reboot_flag=1
#    else
#        echo 'Failed, aborting script'
#        exit 4
#    fi
#fi

# Above 4G Decoding
if ${scelnx_util} /o /ms PCIS006 | grep -Ew '\*\[.*\]Enabled' > /dev/null 2>&1; then
    echo '"Above 4G Decoding" already set to Enabled'
else
    echo -n '"Above 4G Decoding" change to Enabled: '
    if ${scelnx_util} /i /ms PCIS006 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

# SR-IOV Support
if ${scelnx_util} /o /ms PCIS007 | grep -Ew '\*\[.*\]Enabled' > /dev/null 2>&1; then
    echo '"SR-IOV Support" already set to Enabled'
else
    echo -n '"SR-IOV Support" change to Enabled: '
    if ${scelnx_util} /i /ms PCIS007 /qv 01 2>&1 | grep 'Question value imported successfully' > /dev/null; then
        echo 'Success'
        reboot_flag=1
    else
        echo 'Failed, aborting script'
        exit 4
    fi
fi

if [[ ${reboot_flag} == 1 ]]; then
    echo "Reboot require for BIOS changes to take in effect"
fi
exit 0
