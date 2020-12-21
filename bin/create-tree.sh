#!/bin/bash
dir="$1"

[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }

if [ -d "$dir" -a ! -h "$dir" ]
then
    echo "Error: $dir already exists in $(readlink -f ${dir})."
else    
    mkdir "$1"
    cd "$1"

    mkdir client-dir
    mkdir rootca-dir
    mkdir -p client-dir/trusted_ca client-dir/bin
    mkdir -p server-dir/ca server-dir/passwords server-dir/bin
    mkdir client-dir/mailboxes 

fi

# Creates user directories for server and users
input=("addleness" "analects" "annalistic" "anthropomorphologically" "blepharosphincterectomy" "corector" "durwaun" "dysphasia" "encampment" "endoscopic" "exilic" "forfend" "gorbellied" "gushiness" "muermo" "neckar" "outmate" "outroll" "overrich" "philosophicotheological" "pockwood" "polypose" "refluxed" "reinsure" "repine" "scerne" "starshine" "unauthoritativeness" "unminced" "unrosed" "untranquil" "urushinic" "vegetocarbonaceous" "wamara" "whaledom")
for i in ${input[@]}
do 
    (umask 077; mkdir -p client-dir/mailboxes/$i)
    (umask 077; mkdir -p server-dir/mailboxes/$i)
done

j=0
while read line;
do
  echo -n "$line" > "./server-dir/passwords/${input[j]}.txt"
  ((j++))
done < ../original_hashed_pass.txt

# Add a separate password for a specific user; the password is "testuser"

(umask 077; mkdir -p client-dir/mailboxes/$USER)
(umask 077; mkdir -p server-dir/mailboxes/$USER)

# make sure that mkpasswd is installed on your machine first...
mkpasswd --method=sha512crypt --salt=6Q91iwuqLM.qU274 "testuser" > "./server-dir/passwords/${USER}.txt"

# Moves executables into the correct directory
cp ../bin/server ./server-dir/bin/server
cp ../bin/getcert ./client-dir/bin/getcert
cp ../bin/changepw ./client-dir/bin/changepw
cp ../bin/sendmsg ./client-dir/bin/sendmsg
cp ../bin/recvmsg ./client-dir/bin/recvmsg
