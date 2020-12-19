#!/bin/bash

mkdir /home/mailbox

input=("addleness" "analects" "annalistic" "anthropomorphologically" "blepharosphincterectomy" "corector" "durwaun" "dysphasia" "encampment" "endoscopic" "exilic" "forfend" "gorbellied" "gushiness" "muermo" "neckar" "outmate" "outroll" "overrich" "philosophicotheological" "pockwood" "polypose" "refluxed" "reinsure" "repine" "scerne" "starshine" "unauthoritativeness" "unminced" "unrosed" "untranquil" "urushinic" "vegetocarbonaceous" "wamara" "whaledom" "rootca" "server" "message-client")

for i in ${input[@]}
do
        random="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"
        getent group $i || groupadd $i

        if ! id $i &>/dev/null; 
        then 
                useradd -s /usr/bin/false -m -d /home/mailbox/$i  -g $i $i
                echo -e "$random\n$random\n" | passwd $i
        fi
done
