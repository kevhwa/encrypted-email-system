#~/bin/bash

HOME=/home/mushu/security_1/encrypted-messaging-system
HOMEROOT=$HOME/tree/rootca-dir
HOMEINTER=$HOME/tree/client-dir/addleness

PORT=8000

echo "Testing placebo client"
echo " "

echo "GET /file.txt HTTP/1.0\r\n" > $HOME/exampleRequest.txt

openssl s_client -connect localhost:$PORT -cert $HOMEINTER/addleness.cert.pem -key $HOMEINTER/private.key -verify_return_error -CAfile $HOMEROOT/certs/ca.cert.pem  -prexit -quiet -ign_eof < $HOME/exampleRequest.txt