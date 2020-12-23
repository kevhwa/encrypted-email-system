#!/bin/bash

dir="$1"

[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }

echo -e "******** Starting acceptance tests for getcert and changepw executables ********\n";

# Move into client directory

cd $dir/client-dir

echo -e "\n***1. Making a request for a certificate with a bad password... This should fail.***\n"

./bin/getcert -u $USER -p badpass

echo -e "\n***2. Making a request for a certificate with correct password... This should succeed.***\n"

./bin/getcert -u $USER -p testuser

echo -e "\n***3. Making a request to getcert when user already has a certificate... This should ask user to use changepw***\n"

./bin/getcert -u $USER -p testuser

echo -e "\n***4. Attempting to change the password/certificate for the user with incorrect password... This should fail.***\n"

echo "newpass" | ./bin/changepw -u $USER -p badpass

echo -e "\n***5. Attempting to change the password/certificate for the user with correct password... This should succeed.***\n"

echo "newpass" | ./bin/changepw -u $USER -p testuser

echo -e "\n***6. Attemping to change the password/certificate with the old password... This should fail.***\n"

echo "tester" | ./bin/changepw -u $USER -p testuser

echo -e "\n***7. Checking that the new password was successfuly set by attempting to change the password again... This should succeed.***\n"

echo "tester" | ./bin/changepw -u $USER -p newpass

echo -e "\n***8. Making a request to change password for non-existent user... This should fail.***\n"

echo "tester" | ./bin/changepw -u bad_user -p badpass

echo -e "\n***9. Attemping to run getcert executable without the correct arguments... This should report correct usage.***\n"

./bin/getcert -k bad

echo -e "\n***10. Attemping to run changepw executable without the correct arguments... This should report correct usage.***\n"

./bin/changepw -k bad

echo -e "\n***11. User has a message waiting for them on the server... Attempt to changepw should fail.***\n"

sudo echo "This is a mock message file" > ../server-dir/mailboxes/$USER/1010101
echo "testuser" | ./bin/changepw -u $USER -p tester

echo -e "\nClean Up: Resetting user's credentials to their original content...\n"

sudo rm -f ../server-dir/mailboxes/$USER/1010101
echo "testuser" | ./bin/changepw -u $USER -p tester

echo -e "***********************************************************\n";
