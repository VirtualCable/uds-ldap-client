"""LDAP client library for UDS, backed by Rust.

The native implementation lives in the :mod:`._native` extension module.
The public API is defined there and re-exported here.
"""

from ._native import (
    AlreadyExistsError,
    BindError,
    Connection,
    LdapError,
    __version__,
    version,
)

__all__ = [
    "AlreadyExistsError",
    "BindError",
    "Connection",
    "LdapError",
    "__version__",
    "version",
]
