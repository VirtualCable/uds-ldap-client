#!/bin/bash
# Generates the test PKI: a self-signed CA and a server certificate for
# "localhost" (SAN), mounted into the OpenLDAP test container.
# Idempotent: skips generation when the files already exist.
set -e
mkdir -p "$(dirname "$0")/certs"
cd "$(dirname "$0")/certs"

if [ -f ca.crt ] && [ -f ldap.crt ] && [ -f ldap.key ]; then
    exit 0
fi

# CA
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout ca.key -out ca.crt -days 3650 \
    -subj "/CN=UDS Test LDAP CA" 2>/dev/null

# Server key + CSR
openssl req -newkey rsa:2048 -nodes \
    -keyout ldap.key -out ldap.csr \
    -subj "/CN=localhost" 2>/dev/null

# Sign the server certificate with the CA, with the localhost SAN
cat > san.cnf <<'EOF'
subjectAltName = DNS:localhost
basicConstraints = CA:FALSE
EOF
openssl x509 -req -in ldap.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out ldap.crt -days 3650 -extfile san.cnf 2>/dev/null

rm -f ldap.csr san.cnf
echo "Test PKI generated (ca.crt, ldap.crt, ldap.key)"
