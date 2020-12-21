#!/bin/bash
dir="$1"
 
[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }

# Change so that client executables are owned by message-client user and group

chmod 771 ./$dir/client-dir/bin/getcert
chmod 771 ./$dir/client-dir/bin/changepw
chmod 771 ./$dir/client-dir/bin/sendmsg
chmod 771 ./$dir/client-dir/bin/recvmsg

chown message-client:message-client ./$dir/client-dir/bin/getcert
chown message-client:message-client ./$dir/client-dir/bin/changepw
chown message-client:message-client ./$dir/client-dir/bin/sendmsg
chown message-client:message-client ./$dir/client-dir/bin/recvmsg

# Anyone who uses getcert/changepw/sendmsg/recvmsg will be run as message-client group

chmod g+s ./$dir/client-dir/bin/getcert
chmod g+s ./$dir/client-dir/bin/changepw
chmod g+s ./$dir/client-dir/bin/sendmsg
chmod g+s ./$dir/client-dir/bin/recvmsg

# Add permissions to mailbox

input=("addleness" "analects" "annalistic" "anthropomorphologically" "blepharosphincterectomy" "corector" "durwaun" "dysphasia" "encampment" "endoscopic" "exilic" "forfend" "gorbellied" "gushiness" "muermo" "neckar" "outmate" "outroll" "overrich" "philosophicotheological" "pockwood" "polypose" "refluxed" "reinsure" "repine" "scerne" "starshine" "unauthoritativeness" "unminced" "unrosed" "untranquil" "urushinic" "vegetocarbonaceous" "wamara" "whaledom")
for mailbox in ${input[@]}
do
    chown $mailbox:message-client ./$dir/client-dir/mailboxes/$mailbox
    chmod 770 ./$dir/client-dir/mailboxes/$mailbox
done

chown server:server ./$dir/server-dir
chmod 700 ./$dir/server-dir

chown rootca:rootca ./$dir/rootca-dir
chmod 700 ./$dir/rootca-dir
