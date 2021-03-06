#!/bin/bash

dir="$1"

[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }

echo -e "\n************ Starting acceptance tests for recvmsg executable *************";

echo -e "\n**** Setup: Sending two messages to self ****\n"

# remove any existing awaiting files in the user's mailbox to start fresh
sudo find $dir/server-dir/mailboxes/$USER -type f ! -name "*.pem" -delete  # delete all the files except the .pem ones

cd $dir/client-dir

echo "This is a test message" > ./mailboxes/$USER/test1.txt
echo "Hello, nice to meet you" > ./mailboxes/$USER/test2.txt

./bin/sendmsg -f ./mailboxes/$USER/test1.txt -r $USER
./bin/sendmsg -f ./mailboxes/$USER/test2.txt -r $USER

echo -e "\n**** 1. Attempt to retrieve a message from mailbox when 2 messages exist ***\n"

./bin/recvmsg

echo -e "\n**** 2. Attempt to retrieve a message from mailbox when 1 message exists ***\n"

./bin/recvmsg

echo -e "\n**** 3. Attempt to retrieve a message from mailbox when 0 messages exists ***\n"

./bin/recvmsg

echo -e "\n**** 4. Test unexpected command line arguments received... This should report correct usage***\n"

./bin/recvmsg -some random -command -l ine arguments 

echo -e "\n***********************************************************\n";
