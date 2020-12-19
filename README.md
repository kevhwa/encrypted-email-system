# encrypted-messaging-system

### Install 

This will setup the directory structure, generate CA certificates, build executable, and set permissions. Note that this system is designed to be installed on a Ubuntu 20.04.1 LTS VM; there may be incompatibilities if this installation is attempted on another OS.

```
$ make install DEST=tree
```

Open a new terminal and setup the server sandbox. This will bring you right to the server directory where you can start the server (more below).
```
$ sudo ./bin/install-sandbox.sh
```

### Run

#### Start Server

If you are already within the server sandbox:
```
$ ./bin/server
```
Else, if you did not setup the sandbox, `cd` into the correct directory, then run the server:
``
$ cd ./tree/server-dir
$ ./bin/server
```

#### Run getcert

In a separate shell:
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

#### Run changepw

This executable takes the same set of arguments as `getcert`:

```
$ cd tree/client-dir
$ ./bin/changepw -u username -p password 
```
The program will prompt a user to provide a new password.


### Notes on Testing/Debugging

The installation script copies over the executables into the client and server directories. If you don't want to install everything everytime as you develop and you just want to use the latest executables, you can do:
```
$ make all
```
And then run the server via:
```
$ cd tree/server-dir
$ ../../bin/server
```
And the client via:
```
$ cd tree/client-dir
$ ../../bin/getcert -u addleness
```
This approach will maintain the correct paths within the program.

