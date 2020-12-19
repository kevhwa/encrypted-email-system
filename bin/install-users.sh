#!/bin/bash

echo -e "\nInstalling users for messaging system\n"

mkdir -p /home/mailbox

input=("addleness" "analects" "annalistic" "anthropomorphologically" "blepharosphincterectomy" "corector" "durwaun" "dysphasia" "encampment" "endoscopic" "exilic" "forfend" "gorbellied" "gushiness" "muermo" "neckar" "outmate" "outroll" "overrich" "philosophicotheological" "pockwood" "polypose" "refluxed" "reinsure" "repine" "scerne" "starshine" "unauthoritativeness" "unminced" "unrosed" "untranquil" "urushinic" "vegetocarbonaceous" "wamara" "whaledom" "rootca" "server" "message-client")

for i in ${input[@]}
do
        random="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"
        getent group $i || groupadd $i
        id -u $i &>/dev/null || useradd -s /usr/bin/false -m -d /home/mailbox/$i  -g $i $i
        id -u $i &>/dev/null || echo -e "$random\n$random\n" | passwd $i
done
