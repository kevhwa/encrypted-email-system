# encrypted-messaging-system

### Setup and Build

```
$ make install DEST=tree
```

#### Start Server
```
$ cd tree/server-dir
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
