#!/bin/bash
/bin/gzip -1 -f - > /var/crash/$1.$2.$3.gz
