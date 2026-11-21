#!/bin/bash
# Seeds the OpenLDAP test server with the test data (tests/openldap/custom).
# Safe to run repeatedly: ldapadd -c continues past already-existing entries.
#
# Usage: tests/openldap/seed.sh [--fresh]   (--fresh = down -v + up before seeding)
set -e
cd "$(dirname "$0")"

COMPOSE="docker compose -f ../docker-compose.yml"
ADMIN="cn=admin,dc=uds,dc=example,dc=org"
PASSWORD="adminpassword"

if [ "$1" = "--fresh" ]; then
    $COMPOSE down -v
fi

./gen-certs.sh
$COMPOSE up -d

echo "Waiting for slapd to answer..."
for _ in $(seq 1 30); do
    if docker exec uds-test-openldap ldapwhoami -x -D "$ADMIN" -w "$PASSWORD" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
docker exec uds-test-openldap ldapwhoami -x -D "$ADMIN" -w "$PASSWORD" >/dev/null || {
    echo "ERROR: slapd did not come up"
    exit 1
}

docker cp custom/50-uds-seed.ldif uds-test-openldap:/tmp/50-uds-seed.ldif
docker exec uds-test-openldap ldapadd -c -x -D "$ADMIN" -w "$PASSWORD" -f /tmp/50-uds-seed.ldif
echo "Seed done."
