#!/bin/bash

dir="$1"

[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }

# Move into client directory

cd $dir/client-dir

echo -e "\n**** Creating certificates for several mailbox users for testing ****\n"

./bin/getcert -u $USER -p testuser
./bin/getcert -u addleness -p Cardin_pwns
./bin/getcert -u analects -p pickerel_symbiosis
./bin/getcert -u dysphasia -p equably_undies
./bin/getcert -u polypose -p lure_leagued

echo -e "\n**** 1. Attempting to send a message to two users with valid certificate ***\n"

echo "This is a test message" > ./mailboxes/addleness/test.txt

./bin/sendmsg -f ./mailboxes/addleness/test.txt -r $USER analects polypose
