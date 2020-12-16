#~/bin/bash

HOME=/home/mushu/security_1/encrypted-messaging-system
HOMEROOT=$HOME/tree/rootca-dir
HOMEINTER=$HOME/tree/server-dir/ca

PORT=8000

echo "***"
echo "Default placebo server"
echo " "

openssl s_server -accept $PORT -cert $HOMEINTER/certs/ca-chain.cert.pem -cert_chain $HOMEINTER/certs/ca-chain.cert.pem -key $HOMEINTER/private/intermediate.key.pem -certform PEM -CApath $HOMEROOT/certs -CAfile $HOMEROOT/certs/ca.cert.pem -verify_return_error 