# encrypted-messaging-system

#### To setup what we have so far:

Note: "tree" can be any directory name

```
$ ./create-tree.sh tree
$ ./ca/create_root_ca.sh tree
$ ./ca/create_intermediate_ca.sh tree
```

#### To run what we have:
```
$ cd tree
$ ../bin/server
```

In a separate shell
```
$ cd tree
$ ../bin/getcert
```

