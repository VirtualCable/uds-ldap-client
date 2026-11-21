# BSD 3-Clause License
# Copyright (c) 2026, Virtual Cable S.L.
# All rights reserved.
#
# Authors: Adolfo Gómez, dkmaster at dkmon dot com
"""Integration tests: the ldaputil-like layer on top of the native client.

Requires the OpenLDAP test server:

    docker compose -f tests/docker-compose.yml up -d
    (fresh volume the first time, so the seed LDIF is applied)

Run with the shared venv interpreter:

    /home/dkmaster/projects/uds/5.0/env/bin/python -m pytest tests/integration/test_ldaputil_like.py -v
"""

import contextlib
import typing

import pytest

from . import ldaputil_like

HOST = "localhost"
PORT_SSL = 1636
ADMIN = "cn=admin,dc=uds,dc=example,dc=org"
PASSWORD = "adminpassword"
BASE = "dc=uds,dc=example,dc=org"


@pytest.fixture()
def con() -> typing.Iterator[ldaputil_like.Connection]:
    """A working admin connection over LDAPS (self-signed, verification off)."""
    try:
        conn = ldaputil_like.connection(
            ADMIN,
            PASSWORD,
            HOST,
            port=PORT_SSL,
            use_ssl=True,
            verify_ssl=False,
            timeout=5,
        )
    except ldaputil_like.LDAPError as e:
        pytest.skip(f"OpenLDAP test server not reachable: {e}")
    try:
        yield conn
    finally:
        conn.unbind()


@pytest.fixture()
def scratch_dn(con: ldaputil_like.Connection) -> typing.Iterator[str]:
    """A scratch entry DN, removed on teardown however the test ends."""
    dn = f"uid=scratch,ou=users,{BASE}"
    # Teardown-only cleanup: suppress any error (entry may not exist, the
    # native error classes are not mapped at this level).
    with contextlib.suppress(Exception):
        con.delete(dn)
    yield dn
    with contextlib.suppress(Exception):
        con.delete(dn)


def test_as_dict_subtree(con: ldaputil_like.Connection) -> None:
    entries = list(ldaputil_like.as_dict(con, BASE, "(objectClass=inetOrgPerson)"))
    uids = {e["uid"][0] for e in entries}
    assert uids == {"alice", "bob"}


def test_as_dict_attributes(con: ldaputil_like.Connection) -> None:
    entries = list(
        ldaputil_like.as_dict(
            con, BASE, "(uid=alice)", attributes=["uid", "mail", "nonexistent"]
        )
    )
    assert len(entries) == 1
    entry = entries[0]
    # ldaputil parity: every requested attribute is present, missing ones as [""]
    assert entry["uid"] == ["alice"]
    assert entry["mail"] == ["alice@example.org"]
    assert entry["nonexistent"] == [""]
    assert entry["dn"] == f"uid=alice,ou=users,{BASE}"


def test_first_found(con: ldaputil_like.Connection) -> None:
    entry = ldaputil_like.first(
        con, BASE, "inetOrgPerson", "uid", "alice", attributes=["cn"]
    )
    assert entry is not None
    assert entry["cn"] == ["Alice Example"]
    assert entry["_id"] == "alice"


def test_first_not_found(con: ldaputil_like.Connection) -> None:
    assert ldaputil_like.first(con, BASE, "inetOrgPerson", "uid", "nobody") is None


def test_first_escapes_value(con: ldaputil_like.Connection) -> None:
    # Wildcards in the value must not match other users.
    assert ldaputil_like.first(con, BASE, "inetOrgPerson", "uid", "al*") is None


def test_add_and_already_exists(con: ldaputil_like.Connection, scratch_dn: str) -> None:
    attributes = {
        "objectClass": ["inetOrgPerson"],
        "uid": ["scratch"],
        "cn": ["S"],
        "sn": ["T"],
    }
    assert ldaputil_like.add(con, scratch_dn, attributes=attributes) is True
    with pytest.raises(ldaputil_like.AlreadyExistsError):
        ldaputil_like.add(con, scratch_dn, attributes=attributes)


def test_modify_replace_and_reread(
    con: ldaputil_like.Connection, scratch_dn: str
) -> None:
    ldaputil_like.add(
        con,
        scratch_dn,
        attributes={
            "objectClass": ["inetOrgPerson"],
            "uid": ["scratch"],
            "cn": ["S"],
            "sn": ["T"],
        },
    )
    assert (
        ldaputil_like.modify(
            con,
            scratch_dn,
            {"description": [(ldaputil_like.MODIFY_REPLACE, ["modified value"])]},
        )
        is True
    )
    entry = ldaputil_like.first(
        con, BASE, "inetOrgPerson", "uid", "scratch", attributes=["description"]
    )
    assert entry is not None
    assert entry["description"] == ["modified value"]


def test_modify_add_member_rds_pattern(con: ldaputil_like.Connection) -> None:
    """The RDS/AD.py pattern: modify with MODIFY_ADD of a member attribute."""
    group_dn = f"cn=staff,ou=groups,{BASE}"
    user_dn = f"uid=bob,ou=users,{BASE}"
    ldaputil_like.modify(
        con, group_dn, {"member": [(ldaputil_like.MODIFY_ADD, [user_dn])]}
    )
    entries = list(ldaputil_like.as_dict(con, group_dn, "(objectClass=*)", scope=0))
    assert user_dn in entries[0]["member"]
    # Clean up for test idempotency.
    ldaputil_like.modify(
        con, group_dn, {"member": [(ldaputil_like.MODIFY_DELETE, [user_dn])]}
    )


def test_modify_with_bytes_values(
    con: ldaputil_like.Connection, scratch_dn: str
) -> None:
    """windows_domain-style password handling: bytes values on modify."""
    ldaputil_like.add(
        con,
        scratch_dn,
        attributes={
            "objectClass": ["inetOrgPerson"],
            "uid": ["scratch"],
            "cn": ["S"],
            "sn": ["T"],
        },
    )
    ldaputil_like.modify(
        con, scratch_dn, {"userPassword": [(ldaputil_like.MODIFY_REPLACE, [b"newpw"])]}
    )
    entry = ldaputil_like.first(
        con, BASE, "inetOrgPerson", "uid", "scratch", attributes=["userPassword"]
    )
    assert entry is not None
    # OpenLDAP returns the hash, so just check the attribute changed.
    assert entry["userPassword"][0] != b"newpw"


def test_recursive_delete(con: ldaputil_like.Connection) -> None:
    """windows_domain pattern: delete an OU tree."""
    ou_dn = f"ou=scratch-ou,{BASE}"
    child_dn = f"uid=child,{ou_dn}"
    ldaputil_like.add(
        con,
        ou_dn,
        attributes={"objectClass": ["organizationalUnit"], "ou": ["scratch-ou"]},
    )
    ldaputil_like.add(
        con,
        child_dn,
        attributes={
            "objectClass": ["inetOrgPerson"],
            "uid": ["child"],
            "cn": ["C"],
            "sn": ["C"],
        },
    )
    ldaputil_like.delete(con, ou_dn, depth=1)
    assert (
        ldaputil_like.first(con, BASE, "organizationalUnit", "ou", "scratch-ou") is None
    )
    assert ldaputil_like.first(con, BASE, "inetOrgPerson", "uid", "child") is None


def test_get_root_dse(con: ldaputil_like.Connection) -> None:
    dse = ldaputil_like.get_root_dse(con)
    assert dse is not None
    assert dse["dn"] == ""
    assert "supportedLDAPVersion" in dse


def test_bind_error() -> None:
    with pytest.raises(ldaputil_like.BindError):
        ldaputil_like.connection(
            ADMIN, "wrong-password", HOST, port=PORT_SSL, use_ssl=True, verify_ssl=False
        )


def test_connect_error() -> None:
    with pytest.raises(ldaputil_like.LDAPError) as excinfo:
        ldaputil_like.connection(
            ADMIN,
            PASSWORD,
            "localhost",
            port=16361,
            use_ssl=True,
            verify_ssl=False,
            timeout=2,
        )
    assert not isinstance(excinfo.value, ldaputil_like.BindError)


def _server_ca_pem() -> str:
    """The CA certificate of the test server, generated by gen-certs.sh."""
    from pathlib import Path

    path = Path(__file__).parent.parent / "openldap" / "certs" / "ca.crt"
    return path.read_text()


def test_verify_ssl_with_custom_ca(con: ldaputil_like.Connection) -> None:
    """The provider "certificate" path: verify with the PEM content given."""
    try:
        ca_pem = _server_ca_pem()
    except Exception as e:  # noqa: BLE001 - container may not be reachable
        pytest.skip(f"could not read server certificate: {e}")
    conn = ldaputil_like.connection(
        ADMIN,
        PASSWORD,
        HOST,
        port=PORT_SSL,
        use_ssl=True,
        verify_ssl=True,
        certificate_data=ca_pem,
        timeout=5,
    )
    try:
        entries = list(ldaputil_like.as_dict(conn, BASE, "(uid=alice)"))
        assert len(entries) == 1
    finally:
        conn.unbind()


def test_verify_ssl_with_empty_certificate_falls_back_to_system(
    con: ldaputil_like.Connection,
) -> None:
    """Empty certificate string behaves as no custom CA; with the system
    store it must fail verification (self-signed server) with LdapError,
    not succeed nor hang."""
    with pytest.raises(ldaputil_like.LDAPError):
        ldaputil_like.connection(
            ADMIN,
            PASSWORD,
            HOST,
            port=PORT_SSL,
            use_ssl=True,
            verify_ssl=True,
            certificate_data="",
            timeout=5,
        )


def test_dn_from_domain_and_escape() -> None:
    assert ldaputil_like.dn_from_domain("a.b.c") == "dc=a,dc=b,dc=c"
    assert ldaputil_like.dn_from_domain("") == ""
    assert ldaputil_like.escape("al*ice)") == "al\\2aice\\29"
    assert ldaputil_like.preferred_cache_key(
        [("a.b.", 389), ("c.d", 636)]
    ) == ldaputil_like.preferred_cache_key([("c.d", 636), ("a.b", 389)])
