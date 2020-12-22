#!/bin/bash

dir="$1"

[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }

cd $dir/server-dir

(trap 'kill 0' SIGINT; ./bin/server & ./bin/server -a)
