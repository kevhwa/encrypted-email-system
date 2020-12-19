# encrypted-messaging-system

## Install 

First make sure that your virtual machine has build-essential and openssl packages available:
```
$ sudo apt-get update
$ sudo apt-get install build-essential
$ sudo apt-get install libssl-dev 
```

Create the encrypted messaging system with the following make command. This will (1) setup the directory structure, (2) generate CA certificates, (3) build executables, (4) set filesystem permissions, and (5) sandbox the server. This will also start the server within its sandbox automatically. You should see "Waiting for connection..." output to the terminal if the installation was successful. Note that this system is designed to be installed on a Ubuntu 20.04.1 LTS VM; there may be incompatibilities if this installation is attempted on another OS. 
```
$ make install-with-security DEST=tree
```

Note: please make sure that the tree specified does not already exist. If it does:
```
$ sudo rm -rf tree
```

To install the program without security features (i.e., install no uses, file system permissions or sandboxing) for testing and development purposes:
```
$ make install-basic DEST=tree
```

## Run

### Start Server

If you installed the system using `make install-with-security`, the server should have already started for you. Otherwise, if you installed the system with `make install-basic` then `cd` into the correct directory and run the server via:
```
$ cd ./tree/server-dir
$ ./bin/server
```

### Run `getcert`

With the server already started, in a separate shell, run:
```
$ cd tree/client-dir
$ ./bin/getcert -u username -p password
```

Where username is a valid username and password is a valid password for that username. For example:
```
$ ./bin/getcert -u addleness -p Cardin_pwns
```
Note that you can also choose to not provide the password and you will be prompted for it:
```
$ ./bin/getcert -u addleness
Please provide your password (less than 20 characters): 
```

### Run `changepw`

This executable takes the same set of arguments as `getcert`:

```
$ cd tree/client-dir
$ ./bin/changepw -u username -p password 
```
The program will prompt a user to provide a new password that will be saved for their username.
