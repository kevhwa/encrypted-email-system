# encrypted-messaging-system

## Install 

First make sure that your virtual machine has build-essential and openssl packages available:
```
$ sudo apt-get update
$ sudo apt-get install build-essential   # basic essentials
$ sudo apt-get install libssl-dev        # openssl libraries
$ sudo apt-get install whois             # this is to add mkpasswd, so current user can be setup
```

Create the encrypted messaging system with the following make command. This will (1) setup the directory structure, (2) generate CA certificates, (3) build executables, (4) set filesystem permissions, and (5) sandbox the server. Note that this system is designed to be installed on a Ubuntu 20.04.1 LTS VM; there may be incompatibilities if this installation is attempted on another OS. 
```
$ make install-with-security DEST=tree
```

**Please make sure that the tree specified does not already exist.** If it does:
```
$ sudo rm -rf tree
```

To install the program without security features (i.e., install no uses, file system permissions or sandboxing) for testing and development purposes:
```
$ make install-basic DEST=tree
```
For easy testing and debugging, the installation script generates a message-system user for the user installing the system. For example, if a user `charlie` runs the installation script, then `charlie` is a valid message system user. Their password is automatically assigned as `testuser`.

## Run

### Start Server

If you installed the system using `make install-with-security`, the sandboxing setup should have brought you to the server directory, `server-dir`. Otherwise, if you installed the system with `make install-basic` then `cd` into the correct directory. The server needs to be run with client authentication and without (these will listen on different ports). Hence, to run the server:
```
$ ./bin/server  # start the server instance that doesn't verify client certs (port 8080)
```
And in a separate shell:
```
$ ./bin/server -a  # start the server that does verify client certs (port 8081)
```
Note that if you ran `make install-with-security`, you will need to use `sudo` to cd into the `server-dir`:
```
$ sudo -s
$ cd tree/server-dir
$ ./bin/server -a
```

### Client Programs 

#### Run `getcert`

In order to use either `sendmsg` or `recvmsg`, you'll first need a certificate. With the server already started, in a separate shell, run:
```
$ cd tree/client-dir
$ ./bin/getcert -u username -p password
```

Where username is a valid username and password is a valid password for that username. For example:
```
$ ./bin/getcert -u addleness -p Cardin_pwns
$ ./bin/getcert -u meganfrenkel -p testuser   # user created with installation script and automatically given 'testuser' as password
```
Note that you can also choose to not provide the password and you will be prompted for it:
```
$ ./bin/getcert -u addleness
Please provide your password (less than 20 characters): 
```

#### Run `changepw`

This executable takes the same set of arguments as `getcert`:

```
$ cd tree/client-dir
$ ./bin/changepw -u username -p password 
```
The program will prompt a user to provide a new password that will be saved for their username.

#### Run `sendmsg`

This executable will allow you to send message content to all specified recipients. Make sure to include the file path to the file containing the message content and pass along the list of recipients:
```
$ cd tree/client-dir
$ echo "This is a test message" > ./mailboxes/meganfrenkel/test.txt
```
```
$ ./bin/sendmsg -f ./mailboxes/meganfrenkel/test.txt -r addleness analects polypose
```

#### Run `recvmsg`

This executable allows you to retrieve mail from the server. No arguments are required:
```
$ ./bin/recvmsg
```

## Testing

There are few test scripts configured...

After running `make install-basic ...` start the server (this will start both server instances, on both ports):
```
$ ./bin/start_server.sh
```

Then you can then run tests via:
```
$ ./tests/test_certificate_creation.sh
$ ./tests/send_msg.sh
```

