#!/bin/bash

dir="$1"

[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }


# Move into client directory

cd $dir/client-dir

echo -e "1. Making a request for a certificate with a bad password... This should fail.\n"

./bin/getcert -u $USER -p badpass

echo -e "2. Making a request for a certificate with correct password... This should succeed.\n"

./bin/getcert -u $USER -p testuser

echo -e "3. Attempting to change the password/certificate for the user with incorrect password... This should fail.\n"

./bin/changepw -u $USER -p badpass

echo -e "4. Attempting to change the password/certificate for the user with correct password... This should succeed.\n"

echo "newpass" | ./bin/changepw -u $USER -p testuser

echo -e "5. Attemping to change the password/certificate with the old password... This should fail.\n"

echo "tester" | ./bin/changepw -u $USER -p testuser

echo -e "6. Checking that the new password was successfuly set by attempting to change the password again... This should succeed.\n"

echo "tester" | ./bin/changepw -u $USER -p newpass

echo -e "7. Attemping to run getcert executable without the correct arguments... This should report correct usage\n"

./bin/getcert -k bad

echo -e "8. Attemping to run changepw executable without the correct arguments... This should report correct usage\n"

./bin/changepw -k bad

