#!/bin/bash

dir="$1"

[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }

# Move into client directory

cd $dir/client-dir

echo -e "\n************ Starting acceptance tests for sendmsg executable *************";

echo -e "\n**** Setup: Creating certificates for several mailbox users to use in testing... ****\n"

./bin/getcert -u $USER -p testuser
./bin/getcert -u addleness -p Cardin_pwns
./bin/getcert -u analects -p pickerel_symbiosis
./bin/getcert -u dysphasia -p equably_undies
./bin/getcert -u polypose -p lure_leagued

echo -e "\n**** 1. Attempting to send a message to two users with valid certificate ***\n"

echo "This is a test message" > ./mailboxes/$USER/test.txt

./bin/sendmsg -f ./mailboxes/$USER/test.txt -r $USER analects polypose

echo -e "\n**** 2. Test incorrect usage (missing command line arguments)... This should report correct usage.***\n"

./bin/sendmsg 

echo -e "**** 3. Test incorrect usage (bad command line arguments)... This should report correct usage.***\n"

./bin/sendmsg -x set of bad args

echo -e "**** 4. Test incorrect usage (multiple files passed)... This should report correct usage.***\n"

./bin/sendmsg -f ./mailboxes/$USER/test.txt ./mailboxes/$USER/test.txt -r analects polypose

echo -e "**** 4. Test behavior when user passes a file that doesn't exist on the file system accidentally.***\n"

./bin/sendmsg -f this-is-not-a-real-file.txt -r $USER analects polypose

echo -e "\n**** 5. Test attempt to send a message to a user who doesn't exist.***\n"

./bin/sendmsg -f ./mailboxes/$USER/test.txt -r this-user-doesnt-exist

echo -e "\n**** 5. Test attempt to send a message to a user who doesn't have certificate.***\n"

./bin/sendmsg -f ./mailboxes/$USER/test.txt -r whaledom

echo -e "\n**** 6. Test attempt to send a message to a user who doesn't exist and one that does exist.***\n"

./bin/sendmsg -f ./mailboxes/$USER/test.txt -r addleness this-user-doesnt-exist

echo -e "\n**** 7. Test attempt to send a message to two users who don't have certificates.***\n"

./bin/sendmsg -f ./mailboxes/$USER/test.txt -r whaledom repine

echo -e "\n**** 8. Test attempt to send a message to two users who don't have certificates 1 that has one.***\n"

./bin/sendmsg -f ./mailboxes/$USER/test.txt -r whaledom addleness repine

echo -e "\n***** 9. Testing what happens when fed endless data file. ***\n"

../../tests/endless_gen.sh
./bin/sendmsg -f ../../tests/big_test_file.txt -r $USER addleness polypose
rm ../../tests/big_test_file.txt

echo -e "\n***********************************************************\n"
