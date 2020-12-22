#!/bin/bash

dir="$1"

[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }


# Move into client directory

cd $dir/client-dir

echo -e "\n1. Making a request for a certificate with a bad password... This should fail."

./bin/getcert -u $USER -p badpass

echo -e "\n2. Making a request for a certificate with correct password... This should succeed."

./bin/getcert -u $USER -p testuser

echo -e "\n3. Attempting to change the password/certificate for the user with incorrect password... This should fail."

echo "newpass" | ./bin/changepw -u $USER -p badpass

echo -e "\n4. Attempting to change the password/certificate for the user with correct password... This should succeed."

echo "newpass" | ./bin/changepw -u $USER -p testuser

echo -e "\n5. Attemping to change the password/certificate with the old password... This should fail."

echo "tester" | ./bin/changepw -u $USER -p testuser

echo -e "\n6. Checking that the new password was successfuly set by attempting to change the password again... This should succeed."

echo "tester" | ./bin/changepw -u $USER -p newpass

echo -e "7. Attemping to run getcert executable without the correct arguments... This should report correct usage\n"

./bin/getcert -k bad

echo -e "8. Attemping to run changepw executable without the correct arguments... This should report correct usage\n"

./bin/changepw -k bad

echo -e "\n**** Now creating certificates for several mailbox users for further testing...****\n"

./bin/getcert -u addleness -p Cardin_pwns
./bin/getcert -u analects -p pickerel_symbiosis
./bin/getcert -u dysphasia -p equably_undies
./bin/getcert -u overrich -p Freemasonry_bruskest
