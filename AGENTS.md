# uds-ldap-client — working rules

Rust + PyO3 extension providing the LDAP client used by the UDS server.

- All code, documentation, doc-comments, READMEs and commit messages in
  **English**.
- Single crate (no workspace). `Cargo.lock` is committed; all cargo commands
  run with `--locked`.
- Quality gates before finishing any work cycle:
  `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked`
- Do not silence lints with `#[expect]`/`#[allow]` when an idiomatic fix
  exists.
- Logging: `log` crate, bridged to Python logging with `pyo3-log` from the
  Python side. Never `println!` for diagnostics.
- Python stubs (`python/uds_ldap_client/*.pyi`) must stay in sync with the
  native API; they are hand-written on purpose (small, stable surface).
- Distribution: wheels built with maturin (`abi3-py311`), published to GitHub
  releases; the package is **not** published to PyPI. The git repository is
  consumed as a dependency only from the openuds superproject.
- TLS cipher configuration follows the OpenSSL-name translation in
  `src/tls/crypto_provider.rs`: explicit lists must be honoured (fail-fast on
  zero valid suites); rustls defaults when unset.
- **Security findings are internal**: reports, reproduction scripts and risk
  acceptances (`strix_runs/known-risks.md` among them) live **outside the
  public tree** — `strix_runs/` is git-ignored and stays local. Public
  documentation must never describe how a defect can be triggered, only
  ship the fixes and the defensive limits. If a public-facing note about a
  risk is ever needed, it is written at management level and approved by
  the maintainer first.
