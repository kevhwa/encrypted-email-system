#!/bin/bash

# Remove everything, if it already exists
rm -rf messaging-system

# Make a system directory
mkdir messaging-system

# Make directories for client and server applications
cd messaging-system
mkdir client server

# Within the client directory, create directories for all 
cd client 
mkdir certificates private bin

# Within server directory, keep place for authentication, certificates, mailboxes
cd ../server
mkdir authentication certificates mailboxes bin

