#!/usr/bin/env bash
du -bs "${1}" | awk '{print "[ { \"bytes\": "$1", \"dudir\": \""$2"\" } ]";}'
