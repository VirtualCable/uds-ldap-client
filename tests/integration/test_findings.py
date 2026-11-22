# BSD 3-Clause License
# Copyright (c) 2026, Virtual Cable S.L.
# All rights reserved.
#
# Authors: Adolfo Gómez, dkmaster at dkmon dot com
"""Regression tests for the security findings fixed in 0.1.1.

Requires the OpenLDAP test server (tests/openldap/seed.sh).

Not covered here (they need a hostile/fake LDAP server; tracked in the
internal security reports): malformed BER responses (panic containment),
upstream BER parser aborts, rc=10 referral answers carrying partial
entries, and server-returned attributes named "dn" (OpenLDAP schema
rejects creating one).
"""

import threading

import pytest
import uds_ldap_client

HOST = "localhost"
PORT_SSL = 1636
ADMIN = "cn=admin,dc=uds,dc=example,dc=org"
PASSWORD = "adminpassword"
BASE = "dc=uds,dc=example,dc=org"


@pytest.fixture()
def con() -> uds_ldap_client.Connection:
    try:
        return uds_ldap_client.Connection(
            HOST, PORT_SSL, ADMIN, PASSWORD, use_ssl=True, verify_ssl=False, timeout=5
        )
    except uds_ldap_client.LdapError as e:
        pytest.skip(f"OpenLDAP test server not reachable: {e}")


def test_parallel_searches_on_shared_connection_do_not_deadlock(
    con: uds_ldap_client.Connection,
) -> None:
    """vuln-0005 regression: the mutex must be acquired with the GIL already
    released, so concurrent operations cannot freeze the interpreter."""
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            for _ in range(20):
                con.search(BASE, "(uid=alice)", scope=0, attributes=["uid"])
        except BaseException as e:  # noqa: BLE001 - recorded, asserted below
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive(), "a worker thread hung: possible GIL/mutex deadlock"
    assert errors == []


def test_deeply_nested_filter_is_rejected(con: uds_ldap_client.Connection) -> None:
    """vuln-0008 regression: an over-nested filter must be rejected before
    reaching the recursive parser, with a catchable error."""
    deep = "(" * 200 + "cn=x" + ")" * 200
    with pytest.raises(ValueError, match="nesting depth"):
        con.search(BASE, deep)


def test_shallow_deep_filter_still_works(con: uds_ldap_client.Connection) -> None:
    nested = "(&" * 50 + "(uid=alice)" + ")" * 50
    response = con.search(BASE, nested, scope=2, attributes=["uid"])
    assert response["entries"][0]["dn"].startswith("uid=alice")


def test_infinite_timeout_is_rejected() -> None:
    """vuln-0007 regression: non-finite timeouts must raise a catchable
    error, never panic across the FFI boundary."""
    with pytest.raises(ValueError, match="timeout"):
        uds_ldap_client.Connection(
            HOST,
            PORT_SSL,
            ADMIN,
            PASSWORD,
            use_ssl=True,
            verify_ssl=False,
            timeout=float("inf"),
        )


def test_transport_failure_is_not_bind_error() -> None:
    """vuln-0002 regression: a dead server must raise the base LdapError
    (so the per-host backoff marks it bad), never BindError."""
    with pytest.raises(uds_ldap_client.LdapError) as excinfo:
        uds_ldap_client.Connection(
            "localhost",
            16361,
            ADMIN,
            PASSWORD,
            use_ssl=True,
            verify_ssl=False,
            timeout=2,
        )
    assert not isinstance(excinfo.value, uds_ldap_client.BindError)


def test_bind_rejection_is_bind_error() -> None:
    with pytest.raises(uds_ldap_client.BindError):
        uds_ldap_client.Connection(
            HOST, PORT_SSL, ADMIN, "wrong-password", use_ssl=True, verify_ssl=False
        )


def test_modify_rejects_empty_changes(con: uds_ldap_client.Connection) -> None:
    """vuln-0013 regression."""
    with pytest.raises(ValueError, match="at least one change"):
        con.modify(f"uid=alice,ou=users,{BASE}", changes={})


def test_modify_rejects_increment_with_multiple_values(
    con: uds_ldap_client.Connection,
) -> None:
    with pytest.raises(ValueError, match="exactly one value"):
        con.modify(
            f"uid=alice,ou=users,{BASE}",
            changes={"someCounter": [("increment", ["1", "2"])]},
        )


def test_connection_still_works_after_all_fixes(
    con: uds_ldap_client.Connection,
) -> None:
    """Smoke: the fixed client keeps the documented behaviour."""
    response = con.search(BASE, "(objectClass=*)", scope=0)
    assert response["entries"][0]["dn"] == BASE
    assert response["referrals"] == []
    con.unbind()
