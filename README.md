# uds-ldap-client

LDAP client library for UDS, implemented in Rust with [PyO3](https://github.com/PyO3/pyo3)
bindings for Python.

It replaces the `python-ldap3` dependency used by the UDS server for its LDAP
operations, keeping the surface small and focused on what UDS actually needs:
simple bind (with server result message passthrough), search (with referral
control), add, delete (recursive) and modify, over `ldaps` with
explicit TLS version and cipher-suite configuration.

## Development

Requires a Rust toolchain and [maturin](https://www.maturin.rs/) (already
declared in the enterprise `requirements.txt`).

```sh
# Build a wheel into dist/
maturin build

# Build and install into the current environment (development)
maturin develop

# Quality gates
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

## Tests

Unit tests live with the code (`cargo test`). Integration tests use an
OpenLDAP server started with Docker Compose, see `tests/README.md`.

## License

BSD-3-Clause, see `LICENSE`.

