"""Manual smoke test against the OpenLDAP test server.

Start it first:

    docker compose -f tests/docker-compose.yml up -d

Then run with the shared venv interpreter (the wheel must be installed):

    /home/dkmaster/projects/uds/5.0/env/bin/python tests/integration/smoke.py
"""

import logging

import uds_ldap_client

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")

HOST = "localhost"
PORT = 1636  # ldaps
ADMIN = "cn=admin,dc=uds,dc=example,dc=org"
PASSWORD = "adminpassword"
BASE = "dc=uds,dc=example,dc=org"

# 1. Connect + bind over LDAPS (self-signed cert, verification disabled).
conn = uds_ldap_client.Connection(
    HOST,
    PORT,
    ADMIN,
    PASSWORD,
    use_ssl=True,
    verify_ssl=False,
    timeout=5,
)
try:
    # 2. Search the root entry.
    response = conn.search(BASE, "(objectClass=*)", scope=0)
    entries = response["entries"]
    referrals = response["referrals"]
    print(f"search ok: {len(entries)} entries, referrals={referrals}")
    assert entries, "expected at least the base entry"
    print("entry sample:", {k: v for k, v in list(entries[0].items())[:4]})

    # 3. Add a test entry.
    test_dn = f"cn=smoke-test,{BASE}"
    conn.add(
        test_dn,
        attributes={
            "objectClass": ["inetOrgPerson"],
            "cn": ["smoke-test"],
            "sn": ["Test"],
        },
    )
    print("add ok")

    # 4. Modify it (replace description).
    conn.modify(test_dn, changes={"description": [("replace", ["smoke test value"])]})
    response = conn.search(
        test_dn, "(objectClass=*)", scope=0, attributes=["description"]
    )
    assert response["entries"][0]["description"] == ["smoke test value"], response[
        "entries"
    ]
    print("modify + re-read ok")

    # 5. Delete it.
    conn.delete(test_dn)
    print("delete ok")

    # 6. Add it again and expect AlreadyExistsError.
    conn.add(
        test_dn,
        attributes={
            "objectClass": ["inetOrgPerson"],
            "cn": ["smoke-test"],
            "sn": ["Test"],
        },
    )
    try:
        conn.add(
            test_dn,
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": ["smoke-test"],
                "sn": ["Test"],
            },
        )
        raise SystemExit("ERROR: duplicate add did not raise")
    except uds_ldap_client.AlreadyExistsError as e:
        print("already-exists ok:", e)
    conn.delete(test_dn)
finally:
    conn.unbind()
print("unbind ok")

# 7. Bind rejection must raise BindError (not a generic LdapError), with the
#    server's diagnostic text in the message.
try:
    uds_ldap_client.Connection(
        HOST, PORT, ADMIN, "wrong-password", use_ssl=True, verify_ssl=False
    )
    raise SystemExit("ERROR: bad bind did not raise")
except uds_ldap_client.BindError as e:
    print("bind-error ok:", e)

# 8. Connection failure must raise the base LdapError (not BindError).
try:
    uds_ldap_client.Connection(
        "localhost", 16361, ADMIN, PASSWORD, use_ssl=True, verify_ssl=False, timeout=2
    )
    raise SystemExit("ERROR: dead connection did not raise")
except uds_ldap_client.BindError as e:
    raise SystemExit(f"ERROR: dead connection raised BindError: {e}")
except uds_ldap_client.LdapError as e:
    print("connection-error ok:", e)

print("SMOKE TEST PASSED")
