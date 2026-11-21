"""Stubs for the native (Rust) extension module."""

from typing import Any

__version__: str

def version() -> str: ...

class LdapError(Exception):
    """Base error for LDAP client failures."""

class BindError(LdapError):
    """The LDAP server rejected the credentials."""

class AlreadyExistsError(LdapError):
    """The entry or attribute value already exists (result codes 20 / 68)."""

class Connection:
    """Synchronous LDAP connection with a simple bind.

    A rejected bind raises :class:`BindError`; any other failure raises
    :class:`LdapError`. Referrals are never followed.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        *,
        use_ssl: bool = False,
        verify_ssl: bool = True,
        ca_certs_data: str | None = None,
        min_tls_version: str | None = None,
        ciphers: str | None = None,
        client_cert_data: str | None = None,
        client_key_data: str | None = None,
        timeout: float | None = None,
    ) -> None:
        """``ca_certs_data`` is the PEM-encoded CA certificate(s) used to
        verify the server certificate (uses the system store when ``None``).
        ``client_cert_data``/``client_key_data`` enable mutual TLS and must
        be provided together. ``min_tls_version`` is ``"1.2"`` (default)
        or ``"1.3"``. ``ciphers`` is an OpenSSL-style cipher list.
        """

    def search(
        self,
        base: str,
        filter: str,
        *,
        scope: int = 2,
        attributes: list[str] | None = None,
        size_limit: int = 100,
    ) -> dict[str, Any]:
        """Returns ``{"entries": [...], "referrals": [...]}``.

        Each entry is a dict with the ``"dn"`` key plus one key per
        attribute mapped to the list of its values (``str`` or ``bytes``
        for binary attributes). ``scope`` is 0 (base), 1 (onelevel) or
        2 (subtree).
        """

    def add(
        self,
        dn: str,
        *,
        attributes: dict[str, list[str | bytes]],
    ) -> None: ...
    def delete(self, dn: str) -> None: ...
    def modify(
        self,
        dn: str,
        *,
        changes: dict[str, list[tuple[str, list[str | bytes]]]],
    ) -> None:
        """``changes`` maps attribute names to ``(op, values)`` tuples,
        where ``op`` is ``"add"``, ``"delete"``, ``"replace"`` or
        ``"increment"``.
        """

    def unbind(self) -> None: ...
