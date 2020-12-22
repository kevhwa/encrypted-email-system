#!/bin/bash
dir="$1"
 
[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }

# Note: Sudo is purposefully run next to the relevant commands where necessary; this is to keep the value of $USER as the actual user, not root

# Change so that client executables are owned by message-client user and group

sudo chmod 771 ./$dir/client-dir/bin/getcert
sudo chmod 771 ./$dir/client-dir/bin/changepw
sudo chmod 771 ./$dir/client-dir/bin/sendmsg
sudo chmod 771 ./$dir/client-dir/bin/recvmsg
sudo chmod 700 ./$dir/server-dir/bin/server

sudo chown message-client:message-client ./$dir/client-dir/bin/getcert
sudo chown message-client:message-client ./$dir/client-dir/bin/changepw
sudo chown message-client:message-client ./$dir/client-dir/bin/sendmsg
sudo chown message-client:message-client ./$dir/client-dir/bin/recvmsg
sudo chown server:server ./$dir/server-dir/bin/server

# Anyone who uses getcert/changepw/sendmsg/recvmsg will be run as message-client group

sudo chmod g+s ./$dir/client-dir/bin/getcert
sudo chmod g+s ./$dir/client-dir/bin/changepw
sudo chmod g+s ./$dir/client-dir/bin/sendmsg
sudo chmod g+s ./$dir/client-dir/bin/recvmsg

# Add permissions to mailbox

input=("addleness" "analects" "annalistic" "anthropomorphologically" "blepharosphincterectomy" "corector" "durwaun" "dysphasia" "encampment" "endoscopic" "exilic" "forfend" "gorbellied" "gushiness" "muermo" "neckar" "outmate" "outroll" "overrich" "philosophicotheological" "pockwood" "polypose" "refluxed" "reinsure" "repine" "scerne" "starshine" "unauthoritativeness" "unminced" "unrosed" "untranquil" "urushinic" "vegetocarbonaceous" "wamara" "whaledom")
for mailbox in ${input[@]}
do
    sudo chown $mailbox:message-client ./$dir/client-dir/mailboxes/$mailbox
    sudo chmod 770 ./$dir/client-dir/mailboxes/$mailbox
done

# Add permissions for current user as well and provide current user with a password

user=$USER  # need to know real user, not sudo user root when changing these permissions
sudo chown $user:message-client ./$dir/client-dir/mailboxes/$user
sudo chmod 770 ./$dir/client-dir/mailboxes/$user

# Change permissions for server dir and rootca dir

sudo chown message-client:message-client ./$dir/client-dir/trusted_ca
sudo chmod 770 ./$dir/client-dir/trusted_ca

sudo chown server:server ./$dir/server-dir
sudo chmod 700 ./$dir/server-dir

sudo chown rootca:rootca ./$dir/rootca-dir
sudo chmod 700 ./$dir/rootca-dir
