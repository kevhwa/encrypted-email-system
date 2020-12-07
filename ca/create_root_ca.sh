#!/bin/bash
# Use this script to create the Root CA

echo -e "\nCreating Root Certificate Authority\n"

# 1. Create a directory structure; the index.txt and serial files act as a db for signed certificates.
# Move the configuration file for the root server to this location.

cp ./ca/root_ca.cnf ./rootca-dir/root_ca.cnf
cd ./rootca-dir
mkdir -p certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

# 2. Create the root key
# Encrypt the private key with AES256 and output the key to the specified file
# 4096 is the size of the private key that is generated in bits (how to protect the key).

openssl genrsa -aes256 -out private/ca.key.pem 4096
chmod 400 private/ca.key.pem

# 3. Create the self-signed root certificate
# Use the root key just created to create root certificate ca.cert.pm. This certificate
# should have a long expiration date because when it expires, all certificates signed by CA
# become invalid.
#
# Command arguments, explained:
# -config openssl.cnf (allows config file from step #3 to be specified)
# -key private/ca.key.pem (allows us to utilize the key from step 4)
# -new (generates a new certifcate request)
# -x509 (this option outputs a self-signed certificate instead of a certificate request, typically
#        used to generate a self-signed root CA; use extensions configured in config file)
# -days (when -x509 is used, this specifies the number of days to certify the certifcate for)
# -extensions v3_ca (add the v3_ca extension when signing a certificate)
# -out certs/ca.cert.pem (where to save the certificate)

openssl req -config root_ca.cnf \
	-key private/ca.key.pem \
	-new -x509 -days 1000 -sha256 -extensions v3_ca \
    -out certs/ca.cert.pem

chmod 444 ./certs/ca.cert.pem

# 4. Verify the certificate
# The x509 command is used to display certificate information, convert certificates, sign certificate
# requests or edit certificate trust settings. Note that the 'Issuer' and 'Subject' are identical as
# the certificate is self-signed.
#
# Command arguments, explained:
# -noout (display option to prevent output of the encoded version of the certificate)
# -text (display option that prints out full details of certificate in text form)
# -in (filename to read certificate from)
echo "Verifying the created root CA certificate..."
openssl x509 -noout -text -in ./certs/ca.cert.pem

echo -e "\nFinished Creating Root CA!"
