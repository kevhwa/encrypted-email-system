#!bin/bash
dir="$1"

[ $# -eq 0] && { echo "Usage: $0 dir-name"; exit 1; }

if [-d "$dir" -a ! -h "$dir" ]
then
    mkdir "$1"
    cd "$1"

    mkdir client-dir
    mkdir rootca-dir
    mkdir -p server-dir/ca
