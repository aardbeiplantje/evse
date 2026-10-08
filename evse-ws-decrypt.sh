#!/bin/bash
sfn=$1
shift
kfn=$1
shift
[[ ! -f "$sfn" ]] \
    && { echo "usage: $BASH_SOURCE <tcpdumpfile> [<keyfile>]"; exit 1; }
where=$(readlink -f "${BASH_SOURCE}")
websocket_lua_script_file=${where%/*}/ws.lua
tshark -r "$sfn" -2 -R \
    'tcp and (not tcp.len==0) and (websocket || http)' \
    $([ -f "$kfn" ] && echo "-X lua_script1:$(cat $kfn)") \
    -X lua_script:$websocket_lua_script_file \
    -T fields \
    -E occurrence=l \
    -E separator=/t \
    -e tcp.stream \
    -e ip.src \
    -e ip.dst \
    -e text \
    -e _ws.col.Info \
    -e bcencrypt.command 2>/dev/null \
    |awk -F'\t' '{print $6}' \
    |grep -v '^ *$'
