# encrypted-messaging-system

#### To setup what we have so far:

Note: "tree" can be any directory name.
The `create_intermediate_ca.sh` script, for now, asks for a password to access root files in the creation of the certificate. The password here is "pass".

```
$ ./create-tree.sh tree
$ ./ca/create_root_ca.sh tree
$ ./ca/create_intermediate_ca.sh tree
```

#### Build
```
$ make all
```

#### To run what we have:

When prompted for a password on start-up, give "pass".
```
$ cd tree
$ ../bin/server
```

In a separate shell
```
$ cd tree
$ ../bin/getcert
```

