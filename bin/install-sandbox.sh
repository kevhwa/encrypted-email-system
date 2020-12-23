#!/bin/bash

dir="$1"
 
[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }

if [ $USER != 'root' ]
  then
    echo "You must be root to do this."
    exit 1
fi

export J=./$dir/server-dir

mkdir -p $J
mkdir -p $J/{bin,lib64,lib}
mkdir -p $J/lib64/x86_64-linux-gnu
mkdir -p $J/lib/x86_64-linux-gnu

cp /bin/{bash,ls} $J/bin

list="$(ldd /bin/bash | egrep -o '/lib/.*\.[0-9]')"
for i in $list; do cp "$i" "${J}${i}"; done

list="$(ldd /bin/bash | egrep -o '/lib64/.*\.[0-9]')"
for i in $list; do cp "$i" "${J}${i}"; done

list="$(ldd /bin/ls | egrep -o '/lib/.*\.[0-9]')"
for i in $list; do cp "$i" "${J}${i}"; done

list="$(ldd /bin/ls | egrep -o '/lib64/.*\.[0-9]')"
for i in $list; do cp "$i" "${J}${i}"; done

list="$(ldd $J/bin/server | egrep -o '/lib/.*\.[0-9]')"
for i in $list; do cp "$i" "${J}${i}"; done

list="$(ldd $J/bin/server | egrep -o '/lib64/.*\.[0-9]')"
for i in $list; do cp "$i" "${J}${i}"; done

echo -e "\nSandbox installation complete!\n"

sudo chroot $J ./bin/bash
