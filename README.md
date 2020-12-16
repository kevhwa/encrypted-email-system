# encrypted-messaging-system

### Setup

Note: "tree" can be any directory name.
The `create_intermediate_ca.sh` script asks for a password to access root CA files in the creation of the intermediate certificate. The password here is "pass".

```
$ ./create-tree.sh tree
$ ./ca/create_root_ca.sh tree
$ ./ca/create_intermediate_ca.sh tree
```

### Build
```
$ make all
```

### Run

#### Start Server
```
$ cd tree
$ ../bin/server
```

#### Run getcert

In a separate shell:
```
$ cd tree
$ ../bin/getcert -u username -p pass
```
Where username is a valid username and pass is a valid password for that username. For example:

```
$ ../bin/getcert -u addleness -p Cardin_pwns
```
Note that you can also choose to not provide the password and you will be prompted for it:
```
$ ../bin/getcert -u addleness
Please provide your password (less than 20 characters): 
```
