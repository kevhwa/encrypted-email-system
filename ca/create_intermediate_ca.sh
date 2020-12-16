#!/bin/bash
# Use this script to create the Intermediate CA

dir="$1"

[ $# -eq 0 ] && { echo "Usage: $0 dir-name"; exit 1; }

cwd=$(pwd)
export ROOT_CA_DIR=$cwd/$dir/rootca-dir
export INTERMEDIATE_CA_DIR=$cwd/$dir/server-dir/ca

echo "\nCreating Intermediate CA\n"

# 1. Create a directory structure, same as used for root CA files.
# Make sure to move the configuration file for OpenSSL to this directory.
# Note that working with the crl is not part of this assignment, but was added
# for documentation purposes

cp ./ca/intermediate_ca.cnf ./$dir/server-dir/ca/intermediate_ca.cnf
cd ./$dir/server-dir/ca
mkdir -p certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber  # this used to keep track of CRL in normal cases, here just for documentation

# 2. Create the intermediate key (intermediate.key.pem) using AES 256 bit encryption and a password.
# See command-line option eplanation in Root CA section.

#-aes256 -passout pass:pass
echo "Starting genrsa"
openssl genrsa -out ./private/intermediate.key.pem 4096

chmod 400 ./private/intermediate.key.pem

# 3. Create intermediate certificate signing request (CSR)
# Take the intermediate key from step 4 to create a certificate signing request (CSR).
# Note that compared to the root certificate, we do not use -x509 argument.

echo "Attempting to create CSR"
openssl req -config intermediate_ca.cnf -new \
	-key ./private/intermediate.key.pem \
	-out ./csr/intermediate.csr.pem \
	-passin pass:pass

# 4. Create intermediate CA certificate using the root CA
# For the intermediate CA, use the 'v3_intermediate_ca' extension to sign the CSR. The intermediate
# certificate should be valid for a shorter period of time than the root CA. Note that the index.txt
# file stores the certificate database.
#
# Command line arguments, explained:
# -days (the number of days that the certificate is valid for)
# -notext (do not output the text form of a certificate to the output file)
# -md (the message digest to use, algorithm)
# -in (A file containing a single certificate request to be signed by the CA)
# -out (specify the outfile file for certificate)
# -batch (No questions asked, certificate generated automatically)

echo "Attempting to create intermediate CA certificate using root CA"
openssl ca -config ../../rootca-dir/root_ca.cnf -extensions v3_intermediate_ca \
	-key pass -batch \
	-days 500 -notext -md sha256 \
	-in ./csr/intermediate.csr.pem \
	-out ./certs/intermediate.cert.pem

chmod 444 ./certs/intermediate.cert.pem

# 5. Verify the intermediate certificate
# Same as with the root certificate, see details.
# echo "Verifying intermediate certificate"
# openssl x509 -noout -text -in ./certs/intermediate.cert.pem

# 6. Verify that the chain of trust is intact
# It should say OK.
echo "Verifying intermediate CA certificate against root CA certificate - it should say OK"
openssl verify -CAfile ../../rootca-dir/certs/ca.cert.pem ./certs/intermediate.cert.pem

# 7. Complete Certificate chain
# In order to applications to be able to verify the intermediate cert against root, need to add CA certificate chain
# by concatenating the intermediate and root certificates together.
cat ./certs/intermediate.cert.pem ../../rootca-dir/certs/ca.cert.pem > ./certs/ca-chain.cert.pem
chmod 444 ./certs/ca-chain.cert.pem

# Copy trusted CA to client side as well, as this will be needed in client program
cp ./certs/ca-chain.cert.pem ../../client-dir/trusted_ca/ca-chain.cert.pem

echo -e "\nFinished creating Intermediate CA!"
