#!/bin/bash

a=0

touch ../../tests/big_test_file.txt

while [ $a -lt 1000 ]
do
    echo "This is a loop" >> ../../tests/big_test_file.txt
    a=`expr $a + 1`
done
