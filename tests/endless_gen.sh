i=0
while [ $a -lt 1000000000]
do
    echo "This is a loop"
    a=`expr $a + 1`
done