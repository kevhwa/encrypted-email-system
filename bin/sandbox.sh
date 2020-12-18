#!/bin/bash

export J=./tree/server-dir

mkdir -p $J
mkdir -p $J/{bin,lib64,lib}
mkdir -p $J/lib64/x86_64-linux-gnu
mkdir -p $J/lib/x86_64-linux-gnu

cp -v /bin/{bash,ls} $J/bin

list="$(ldd /bin/bash | egrep -o '/lib/.*\.[0-9]')"
for i in $list; do cp  -v "$i" "${J}${i}"; done

list="$(ldd /bin/bash | egrep -o '/lib64/.*\.[0-9]')"
for i in $list; do cp  -v "$i" "${J}${i}"; done

list="$(ldd /bin/ls | egrep -o '/lib/.*\.[0-9]')"
for i in $list; do cp  -v "$i" "${J}${i}"; done

list="$(ldd /bin/ls | egrep -o '/lib64/.*\.[0-9]')"
for i in $list; do cp  -v "$i" "${J}${i}"; done

list="$(ldd $J/bin/server | egrep -o '/lib/.*\.[0-9]')"
for i in $list; do cp  -v "$i" "${J}${i}"; done

list="$(ldd $J/bin/server | egrep -o '/lib64/.*\.[0-9]')"
for i in $list; do cp  -v "$i" "${J}$c{i}"; done

sudo chroot $J /bin/bash