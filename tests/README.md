# LDAP test servers

Integration test servers, started with Docker Compose.

## OpenLDAP

```sh
docker compose -f tests/docker-compose.yml up -d
```

* Plain LDAP: `ldap://localhost:1389`
* LDAPS (self-signed, auto-generated at first start): `ldaps://localhost:1636`
* Base DN: `dc=uds,dc=example,dc=org`
* Admin bind DN: `cn=admin,dc=uds,dc=example,dc=org`, password `adminpassword`

The auto-generated self-signed certificate does not validate against a system
store, so tests must either use `verify_ssl=False` or extract the container CA
to test the custom-CA path (planned, see the integration test suite).

Tear down with `docker compose -f tests/docker-compose.yml down -v`.
