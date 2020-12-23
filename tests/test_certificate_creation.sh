#!/bin/bash

dir="$1"

[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }

echo -e "******** Starting acceptance tests for getcert and changepw executables ********\n";

# Move into client directory

cd $dir/client-dir

echo -e "\n***1. Making a request for a certificate with a bad password... This should fail.***"

./bin/getcert -u $USER -p badpass

echo -e "\n***2. Making a request for a certificate with correct password... This should succeed.***"

./bin/getcert -u $USER -p testuser

echo -e "\n***3. Making a request for a certificate for non-existent user... This should fail.***"

./bin/getcert -u bad_user -p badpass

echo -e "\n***4. Attempting to change the password/certificate for the user with incorrect password... This should fail.***"

echo "newpass" | ./bin/changepw -u $USER -p badpass

echo -e "\n***5. Attempting to change the password/certificate for the user with correct password... This should succeed.***"

echo "newpass" | ./bin/changepw -u $USER -p testuser

echo -e "\n***6. Attemping to change the password/certificate with the old password... This should fail.***"

echo "tester" | ./bin/changepw -u $USER -p testuser

echo -e "\n***7. Checking that the new password was successfuly set by attempting to change the password again... This should succeed.***"

echo "tester" | ./bin/changepw -u $USER -p newpass

echo -e "\n***8. Making a request to change password for non-existent user... This should fail.***"

echo "tester" | ./bin/changepw -u bad_user -p badpass

echo -e "\n***9. Attemping to run getcert executable without the correct arguments... This should report correct usage.***\n"

./bin/getcert -k bad

echo -e "\n***10. Attemping to run changepw executable without the correct arguments... This should report correct usage.***\n"

./bin/changepw -k bad

echo -e "\nClean Up: Resetting user's credentials to their original content...\n"

echo "testuser" | ./bin/changepw -u $USER -p tester

echo -e "***********************************************************\n";
