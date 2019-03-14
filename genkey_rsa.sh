#!/bin/sh
# generate key and self-signed certificate for RSA 1024
# Usage: genkey_rsa.sh [key_file [cert_file]]

# files to be generated
KEY=${1:-eckey.pem}
CERT=${2:-eccert.pem}


# create key
openssl genrsa -out $KEY 2048

# create self-signed certificate
openssl req -new -x509 -key $KEY -out $CERT -days 730 2>/dev/null <<EOF
NW
Nowhere Land
Nowhere City
Nowhere Company
Nowhere Team
nowhere.nw
nowhereman@nowhere.nw
EOF


# dump private key info
echo "### $KEY info ###"
openssl rsa -text -noout -in $KEY
echo

# dump certifiace info
echo "### $CERT info ###"
openssl x509 -text -noout -in $CERT
echo

