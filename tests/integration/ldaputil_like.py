# BSD 3-Clause License
# Copyright (c) 2026, Virtual Cable S.L.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Authors: Adolfo Gómez, dkmaster at dkmon dot com
"""Minimal re-implementation of ``uds.core.util.ldaputil`` on top of
``uds_ldap_client``.

It reproduces, with the same call patterns, the logic that the UDS modules
(SimpleLDAP, RegexLdap, EDirectory, ActiveDirectory, windows_domain,
RDS/AD.py) exercise today against python-ldap3, so the native client can be
validated before wiring the real ``ldaputil`` to it.

Not ported here (stays in the real ldaputil): pool/backoff logic, cache
plumbing and Django-dependent bits.
"""

import collections.abc
import hashlib
import typing

from uds_ldap_client import AlreadyExistsError as _NativeAlreadyExists
from uds_ldap_client import BindError as _NativeBind
from uds_ldap_client import Connection
from uds_ldap_client import LdapError as _NativeError

# Scope constants, matching ldaputil's re-exports (ldap3 BASE/LEVEL/SUBTREE).
SCOPE_BASE = 0
SCOPE_ONELEVEL = 1
SCOPE_SUBTREE = 2

# Modify operations, matching the semantics of ldaputil's re-exports
# (ldap3 MODIFY_ADD / MODIFY_DELETE / MODIFY_REPLACE / MODIFY_INCREMENT).
MODIFY_ADD = "add"
MODIFY_DELETE = "delete"
MODIFY_REPLACE = "replace"
MODIFY_INCREMENT = "increment"

ALL_ATTRIBUTES = "*"

LDAPResultType = dict[str, typing.Any]


class LDAPError(Exception):
    pass


class BindError(LDAPError):
    """The server answered but rejected the credentials."""


class AlreadyExistsError(LDAPError):
    """The entry or attribute value already exists."""


class LDAPReferralError(LDAPError):
    """A search returned referrals (when ``raise_on_referrals=True``)."""

    referrals: list[str]
    partial_results: list[LDAPResultType]

    def __init__(
        self,
        referrals: collections.abc.Iterable[str],
        partial_results: collections.abc.Iterable[LDAPResultType] = (),
    ) -> None:
        normalized = [r for r in referrals if r]
        super().__init__(f"LDAP referrals: {normalized}")
        self.referrals = normalized
        self.partial_results = list(partial_results)


class CaseInsensitiveDict(dict[str, typing.Any]):
    """Minimal stand-in for ``uds.core.util.utils.CaseInsensitiveDict``.

    Stores keys as given, lookups are case-insensitive.
    """

    def _find(self, key: str) -> str:
        if dict.__contains__(self, key):
            return key
        lowered = key.lower()
        for k in dict.keys(self):
            if k.lower() == lowered:
                return k
        raise KeyError(key)

    @typing.override
    def __contains__(self, key: object) -> bool:
        try:
            return self._find(str(key)) in self
        except KeyError:
            return False

    @typing.override
    def __getitem__(self, key: str) -> typing.Any:
        return super().__getitem__(self._find(key))


def _map_error(e: Exception, operation: str) -> LDAPError:
    if isinstance(e, _NativeBind):
        return BindError(str(e))
    if isinstance(e, _NativeAlreadyExists):
        return AlreadyExistsError(str(e))
    return LDAPError(f"{operation}: {e}")


def escape(value: str) -> str:
    """Escape filter chars for LDAP search filters (as ldaputil.escape)."""
    return (
        value.replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\0", "\\00")
    )


def connection(
    username: str,
    passwd: str,
    host: str,
    *,
    port: int = -1,
    read_only: bool = True,  # kept for signature parity with ldaputil
    use_ssl: bool = False,
    timeout: int = 3,
    verify_ssl: bool = False,
    certificate_data: str | None = None,  # CA PEM content, not a file
    min_tls_version: str | None = None,
    ciphers: str | None = None,
) -> Connection:
    """Connects and binds, mapping native exceptions to the ldaputil kinds."""
    if port == -1:
        port = 636 if use_ssl else 389
    try:
        return Connection(
            host,
            port,
            username,
            passwd,
            use_ssl=use_ssl,
            verify_ssl=verify_ssl,
            # Empty string must behave as "no custom CA" (system store).
            ca_certs_data=certificate_data or None,
            min_tls_version=min_tls_version,
            ciphers=ciphers,
            timeout=timeout,
        )
    # _NativeBind, _NativeAlreadyExists are direct subclasses of _NativeError, so we catch the base and map it.
    except _NativeError as e:
        raise _map_error(e, "Connection") from e


def as_dict(
    con: Connection,
    base: str,
    ldap_filter: str,
    *,
    attributes: collections.abc.Iterable[str] | None = None,
    limit: int = 100,
    scope: int = SCOPE_SUBTREE,
    raise_on_referrals: bool = False,
) -> collections.abc.Generator[LDAPResultType, None, None]:
    """Searches and yields one dict per entry (values always lists)."""
    attr_list = list(attributes) if attributes else None
    try:
        response = con.search(
            base,
            ldap_filter,
            scope=scope,
            attributes=attr_list,
            size_limit=limit,
        )
    except Exception as e:
        raise _map_error(e, "Search") from e

    entries = response["entries"]
    if raise_on_referrals and response["referrals"]:
        raise LDAPReferralError(response["referrals"], partial_results=list(entries))

    for entry in entries:
        dct = CaseInsensitiveDict()
        if attr_list:
            # ldaputil parity: requested-but-missing attributes come back as [""].
            for attr in attr_list:
                dct[attr] = entry.get(attr, [""])
        else:
            for attr, values in entry.items():
                if attr != "dn":
                    dct[attr] = values
        dct["dn"] = entry["dn"]
        yield dct


def first(
    con: Connection,
    base: str,
    object_class: str,
    field: str,
    value: str,
    *,
    attributes: collections.abc.Iterable[str] | None = None,
    max_entries: int = 50,
    raise_on_referrals: bool = False,
) -> LDAPResultType | None:
    """Searches for the entry matching ``objectClass`` + ``field=value``."""
    value = escape(value)
    attr_list = [field] + list(attributes) if attributes else [field]
    ldap_filter = f"(&(objectClass={object_class})({field}={value}))"
    try:
        gen = as_dict(
            con,
            base,
            ldap_filter,
            attributes=attr_list,
            limit=max_entries,
            raise_on_referrals=raise_on_referrals,
        )
        obj = next(gen)
    except LDAPReferralError:
        raise
    except StopIteration:
        return None
    obj["_id"] = value
    return obj


def add(
    con: Connection,
    dn: str,
    *,
    attributes: dict[str, list[bytes | str]],
) -> bool:
    """Adds a new entry; raises on failure (AlreadyExistsError on duplicate)."""
    try:
        con.add(dn, attributes=attributes)
        return True
    except Exception as e:
        raise _map_error(e, "Add") from e


def delete(con: Connection, dn: str, *, depth: int = 1) -> None:
    """Deletes an entry and its children down to ``depth`` (as ldaputil)."""
    try:
        response = con.search(dn, "(objectClass=*)", scope=SCOPE_ONELEVEL)
        for entry in response["entries"]:
            delete(con, entry["dn"], depth=depth - 1)
        con.delete(dn)
    except Exception as e:
        raise _map_error(e, "Delete") from e


def recursive_delete(con: Connection, base_dn: str) -> None:
    """Deletes all direct children and the entry itself."""
    delete(con, base_dn, depth=1)


def modify(
    con: Connection,
    dn: str,
    changes: dict[str, list[tuple[str, list[bytes | str]]]],
) -> bool:
    """Performs a modify operation; raises on failure."""
    try:
        con.modify(dn, changes=changes)
        return True
    except Exception as e:
        raise _map_error(e, "Modify") from e


def get_root_dse(con: Connection) -> LDAPResultType | None:
    """Returns the root DSE (search base "" with operational attributes)."""
    try:
        response = con.search(
            "", "(objectClass=*)", scope=SCOPE_BASE, attributes=["*", "+"]
        )
    except Exception as e:
        raise _map_error(e, "Search") from e
    entries = response["entries"]
    if not entries:
        return None
    return dict(entries[0])


def dn_from_domain(domain: str) -> str:
    """'a.b.c' -> 'dc=a,dc=b,dc=c'. Empty / whitespace input -> empty string."""
    parts = [p.strip() for p in domain.split(".") if p.strip()]
    if not parts:
        return ""
    return ",".join(f"dc={p}" for p in parts)


def preferred_cache_key(hosts: collections.abc.Sequence[tuple[str, int]]) -> str:
    """Cache key holding the preferred DC for this pool of servers."""
    pool = "|".join(sorted(f"{h.lower().rstrip('.')}:{p}" for h, p in hosts))
    return f"ldap.preferred.{hashlib.sha256(pool.encode()).hexdigest()[:16]}"
