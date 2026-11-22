// BSD 3-Clause License
// Copyright (c) 2026, Virtual Cable S.L.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Authors: Adolfo Gómez, dkmaster at dkmon dot com
//! Python-facing LDAP connection.

use std::{collections::HashSet, sync::Mutex, time::Duration};

use ldap3::{LdapConn, LdapConnSettings, Mod, ResultEntry, Scope, SearchEntry, SearchOptions};
use pyo3::{
    exceptions::PyValueError,
    prelude::*,
    types::{PyAny, PyBytes, PyDict, PyList},
};

use crate::{
    errors::{AlreadyExistsError, BindError, LdapError},
    tls::client_config::client_config,
};

/// LDAP result codes that map to `AlreadyExistsError`.
///
/// 20 = attributeOrValueExists, 68 = entryAlreadyExists (RFC 4511 A.1).
const ALREADY_EXISTS_CODES: [u32; 2] = [20, 68];

/// LDAP referral result code (RFC 4511 A.1).
const REFERRAL_CODE: u32 = 10;

/// Maximum allowed search filter nesting depth.
///
/// The `ldap3` filter grammar is implemented as a recursive-descent parser
/// without a depth counter; a filter nested deep enough overflows the
/// parser's stack. Enforcing the limit here, before the filter reaches
/// the parser, closes that failure class at our boundary.
const MAX_FILTER_DEPTH: usize = 100;

/// Internal error of the blocking operations, so that exceptions are
/// materialised outside the GIL-released region.
enum OpError {
    /// Operation result with an error code (rc, diagnostic text).
    Result(u32, String),
    /// Any other failure.
    Failed(String),
}

impl OpError {
    fn into_pyerr(self, operation: &str) -> PyErr {
        match self {
            Self::Result(rc, text) => {
                if ALREADY_EXISTS_CODES.contains(&rc) {
                    AlreadyExistsError::new_err(format!(
                        "{operation} operation failed: rc={rc} text={text:?}"
                    ))
                } else {
                    LdapError::new_err(format!(
                        "{operation} operation failed: rc={rc} text={text:?}"
                    ))
                }
            }
            Self::Failed(msg) => LdapError::new_err(format!("{operation} operation failed: {msg}")),
        }
    }
}

/// A single attribute value, either a string or binary data.
enum AttrValue {
    Str(String),
    Bytes(Vec<u8>),
}

/// A search entry before conversion to a Python dict.
struct RawEntry {
    dn: String,
    attrs: Vec<(String, Vec<AttrValue>)>,
}

/// Converts a [`SearchEntry`] to the intermediate representation.
///
/// `ldap3`'s `SearchEntry::construct` panics on malformed server data
/// (documented behaviour, implemented with assertions over BER); callers
/// must run this inside a panic containment boundary.
fn search_entry_to_raw(entry: ResultEntry) -> RawEntry {
    let se = SearchEntry::construct(entry);
    let mut attrs: Vec<(String, Vec<AttrValue>)> = se
        .attrs
        .into_iter()
        .map(|(k, vals)| (k, vals.into_iter().map(AttrValue::Str).collect()))
        .collect();
    attrs.extend(
        se.bin_attrs
            .into_iter()
            .map(|(k, vals)| (k, vals.into_iter().map(AttrValue::Bytes).collect())),
    );
    RawEntry { dn: se.dn, attrs }
}

/// Parses a timeout expressed in seconds.
///
/// Non-finite (infinite, NaN) or out-of-range values must be rejected with
/// an error, never converted into a panic: `Duration::from_secs_f64`
/// panics on them, and a panic escaping the FFI boundary becomes a
/// `PanicException` (`BaseException`), which callers do not catch.
fn parse_timeout(seconds: f64) -> Result<Option<Duration>, String> {
    if !seconds.is_finite() {
        return Err(format!(
            "invalid timeout {seconds:?}: it must be a finite number"
        ));
    }
    if seconds <= 0.0 {
        return Ok(None);
    }
    Duration::try_from_secs_f64(seconds)
        .map(Some)
        .map_err(|e| format!("invalid timeout {seconds:?}: {e}"))
}

/// Computes the maximum parenthesis nesting depth of a search filter,
/// honouring backslash escapes (`\28` / `\29` do not open or close groups,
/// and an escaped parenthesis does not count either).
fn filter_max_depth(filter: &str) -> usize {
    let mut depth = 0usize;
    let mut max = 0usize;
    let mut escaped = false;
    for ch in filter.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '(' => {
                depth += 1;
                max = max.max(depth);
            }
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

/// Extracts a Python `str | bytes` value as raw bytes.
fn value_to_bytes(py: Python<'_>, value: Py<PyAny>) -> PyResult<Vec<u8>> {
    let bound = value.bind(py);
    if let Ok(bytes) = bound.extract::<Vec<u8>>() {
        return Ok(bytes);
    }
    let text: String = bound.extract()?;
    Ok(text.into_bytes())
}

/// Extracts a Python `list[str | bytes]` as a set of byte values.
fn values_to_set(py: Python<'_>, values: Vec<Py<PyAny>>) -> PyResult<HashSet<Vec<u8>>> {
    values.into_iter().map(|v| value_to_bytes(py, v)).collect()
}

/// Parses the changes dict of `modify`: `{attr: [(op, [values]), ...]}`.
fn parse_changes(py: Python<'_>, changes: &Bound<'_, PyDict>) -> PyResult<Vec<Mod<Vec<u8>>>> {
    let mut mods: Vec<Mod<Vec<u8>>> = Vec::new();
    for (key, ops) in changes.iter() {
        let attr: String = key.extract()?;
        for op_tuple in ops.try_iter()? {
            let (op, values): (String, Vec<Py<PyAny>>) = op_tuple?.extract()?;
            let set = values_to_set(py, values)?;
            let name = attr.clone().into_bytes();
            let m = match op.as_str() {
                "add" => Mod::Add(name, set),
                "delete" => Mod::Delete(name, set),
                "replace" => Mod::Replace(name, set),
                "increment" => {
                    // RFC 4527 increments by a single value; applying an
                    // arbitrary element of several would be a silent bug.
                    if set.len() != 1 {
                        return Err(PyValueError::new_err(format!(
                            "increment of {attr} requires exactly one value"
                        )));
                    }
                    Mod::Increment(name, set.into_iter().next().expect("exactly one value"))
                }
                other => {
                    return Err(PyValueError::new_err(format!(
                        "unknown modify operation {other:?} (expected add, delete, replace or increment)"
                    )));
                }
            };
            mods.push(m);
        }
    }
    Ok(mods)
}

#[pyclass]
pub struct Connection {
    inner: Mutex<Option<LdapConn>>,
    /// Per-operation timeout, re-armed before every operation: `ldap3`
    /// consumes it (`timeout.take()`) on first use, so arming it once in
    /// the constructor would leave every later operation without a
    /// deadline.
    op_timeout: Option<Duration>,
}

impl Connection {
    /// Runs a blocking operation against the stored connection with the
    /// GIL released. Exceptions are materialised outside the closure.
    ///
    /// The mutex is acquired *inside* the GIL-released region: a thread
    /// waiting for the lock must not hold the GIL while waiting, or the
    /// interpreter freezes (the lock holder cannot finish without
    /// re-acquiring the GIL). The acquisition is poison-tolerant, and the
    /// blocking call is panic-contained: `ldap3` documents that its BER
    /// parsers panic on malformed server responses, and a panic escaping
    /// the FFI boundary surfaces as `PanicException`, a `BaseException`
    /// the documented error handlers do not catch.
    fn with_conn<T: Send>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&mut LdapConn) -> Result<T, OpError> + Send,
    ) -> Result<T, OpError> {
        py.detach(move || {
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(conn) = guard.as_mut() else {
                return Err(OpError::Failed("connection is closed".to_owned()));
            };
            if let Some(timeout) = self.op_timeout {
                conn.with_timeout(timeout);
            }
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(conn))) {
                Ok(result) => result,
                Err(_) => {
                    // A panic can leave the protocol byte stream
                    // desynchronised: discard the connection. Dropping it
                    // releases the socket, so no descriptor is retained.
                    *guard = None;
                    Err(OpError::Failed(
                        "the LDAP library panicked while processing the server response".to_owned(),
                    ))
                }
            }
        })
    }
}

#[pymethods]
impl Connection {
    /// Connects and performs a simple bind. A rejected bind raises
    /// `BindError`; any other failure (transport, TLS, protocol) raises
    /// `LdapError`.
    #[new]
    #[pyo3(signature = (
        host,
        port,
        username,
        password,
        *,
        use_ssl = false,
        verify_ssl = true,
        ca_certs_data = None,
        min_tls_version = None,
        ciphers = None,
        client_cert_data = None,
        client_key_data = None,
        timeout = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        host: String,
        port: u16,
        username: String,
        password: String,
        use_ssl: bool,
        verify_ssl: bool,
        ca_certs_data: Option<String>,
        min_tls_version: Option<String>,
        ciphers: Option<String>,
        client_cert_data: Option<String>,
        client_key_data: Option<String>,
        timeout: Option<f64>,
    ) -> PyResult<Self> {
        let op_timeout = timeout
            .map(parse_timeout)
            .transpose()
            .map_err(PyValueError::new_err)?
            .flatten();

        if !use_ssl
            && (ca_certs_data.is_some()
                || min_tls_version.is_some()
                || ciphers.is_some()
                || client_cert_data.is_some()
                || client_key_data.is_some())
        {
            log::warn!(
                "TLS options (ca_certs_data/min_tls_version/ciphers/client_cert_*) are ignored \
                 because use_ssl is false: the connection runs in cleartext"
            );
        }
        if !verify_ssl {
            log::warn!("LDAP certificate verification is disabled (verify_ssl=false)");
        }

        let scheme = if use_ssl { "ldaps" } else { "ldap" };
        let url = format!("{scheme}://{host}:{port}");

        let mut settings = LdapConnSettings::new();
        if let Some(seconds) = op_timeout {
            settings = settings.set_conn_timeout(seconds);
        }
        if use_ssl {
            let config = client_config(
                ciphers.as_deref(),
                min_tls_version.as_deref(),
                ca_certs_data.as_deref().map(str::as_bytes),
                verify_ssl,
                client_cert_data.as_deref().map(str::as_bytes),
                client_key_data.as_deref().map(str::as_bytes),
            )
            .map_err(|e| LdapError::new_err(e.to_string()))?;
            settings = settings.set_config(config);
        }

        enum ConnectError {
            /// Transport, TLS or protocol failure: never a credential
            /// problem, so the per-host backoff logic must treat it as a
            /// failed host.
            Connect(String),
            /// The server answered and rejected the credentials.
            Bind(String),
        }

        // Blocking connect + bind with the GIL released. The whole exchange
        // is panic-contained: `ldap3`'s result parser is written with
        // assertions over server-supplied BER, so a malformed BindResponse
        // panics inside the library (must become `LdapError`, never a
        // `PanicException` escaping to Python).
        let conn = py
            .detach(move || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut conn = LdapConn::with_settings(settings, &url).map_err(|e| {
                        ConnectError::Connect(format!("{host}:{port}: {e}"))
                    })?;
                    let result = conn.simple_bind(&username, &password);
                    match result {
                        Err(e) => {
                            // Transport/protocol failure of the bind
                            // exchange: not a credential rejection.
                            Err(ConnectError::Connect(format!("{host}:{port}: {e}")))
                        }
                        Ok(result) if result.rc != 0 => {
                            // Surface the LDAP result message (e.g. AD
                            // "AcceptSecurityContext error, data 773, ...")
                            // so callers can distinguish an expired password
                            // from a generic auth failure. The message is
                            // interpolated with `Debug` formatting so a
                            // hostile server cannot forge log lines.
                            let text = if result.text.is_empty() {
                                format!("result code {rc}", rc = result.rc)
                            } else {
                                result.text
                            };
                            Err(ConnectError::Bind(format!(
                                "{host}:{port} as {username:?}: {text:?}"
                            )))
                        }
                        Ok(_) => Ok(conn),
                    }
                }))
                .unwrap_or_else(|_| {
                    Err(ConnectError::Connect(format!(
                        "{host}:{port}: the LDAP library panicked while processing the server response"
                    )))
                })
            })
            .map_err(|e| match e {
                ConnectError::Connect(msg) => {
                    LdapError::new_err(format!("Could not connect to LDAP server {msg}"))
                }
                ConnectError::Bind(msg) => {
                    BindError::new_err(format!("Could not bind to LDAP server {msg}"))
                }
            })?;

        Ok(Self {
            inner: Mutex::new(Some(conn)),
            op_timeout,
        })
    }

    /// Performs a search and returns a dict with `entries` and `referrals`.
    ///
    /// Each entry is a dict with the `"dn"` key plus one key per attribute
    /// mapped to the list of its values (strings, or bytes for binary
    /// attributes).
    ///
    /// Referrals are never followed; the caller decides what to do with
    /// them (`raise_on_referrals` in the Python-side wrapper).
    #[pyo3(signature = (
        base,
        filter,
        *,
        scope = 2,
        attributes = None,
        size_limit = 100,
    ))]
    fn search(
        &self,
        py: Python<'_>,
        base: &str,
        filter: &str,
        scope: u8,
        attributes: Option<Vec<String>>,
        size_limit: i32,
    ) -> PyResult<Py<PyDict>> {
        if filter_max_depth(filter) > MAX_FILTER_DEPTH {
            return Err(PyValueError::new_err(format!(
                "search filter exceeds the maximum nesting depth of {MAX_FILTER_DEPTH}"
            )));
        }
        let scope = match scope {
            0 => Scope::Base,
            1 => Scope::OneLevel,
            2 => Scope::Subtree,
            other => {
                return Err(PyValueError::new_err(format!(
                    "invalid search scope {other} (expected 0=base, 1=onelevel, 2=subtree)"
                )));
            }
        };
        let attrs = attributes.unwrap_or_default();

        let (raw_entries, referrals): (Vec<RawEntry>, Vec<String>) = self
            .with_conn(py, |conn| {
                conn.with_search_options(SearchOptions::new().sizelimit(size_limit));
                let result = conn
                    .search(base, scope, filter, attrs)
                    .map_err(|e| OpError::Failed(e.to_string()))?;
                // Take the entries and the result apart directly: on a
                // referral answer (rc=10) the entries already received are
                // preserved as partial results instead of being dropped.
                let (entries, res) = (result.0, result.1);
                if res.rc != 0 && !(res.rc == REFERRAL_CODE && !res.refs.is_empty()) {
                    return Err(OpError::Result(res.rc, res.text));
                }
                Ok((
                    entries.into_iter().map(search_entry_to_raw).collect(),
                    res.refs,
                ))
            })
            .map_err(|e| e.into_pyerr("Search"))?;

        let response = PyDict::new(py);
        let entries = PyList::empty(py);
        for raw in raw_entries {
            let dict = PyDict::new(py);
            dict.set_item("dn", raw.dn)?;
            for (attr, values) in raw.attrs {
                // "dn" is reserved for the entry DN: a server-returned
                // attribute with that name must not overwrite it.
                if attr.eq_ignore_ascii_case("dn") {
                    continue;
                }
                let list = PyList::empty(py);
                for value in values {
                    match value {
                        AttrValue::Str(text) => list.append(text)?,
                        AttrValue::Bytes(bytes) => list.append(PyBytes::new(py, &bytes))?,
                    }
                }
                dict.set_item(attr, list)?;
            }
            entries.append(dict)?;
        }
        response.set_item("entries", entries)?;
        response.set_item("referrals", referrals)?;
        Ok(response.into())
    }

    /// Adds a new entry. `attributes` maps attribute names to lists of
    /// values (`str` or `bytes`). Raises `AlreadyExistsError` when the
    /// entry or a value already exists.
    #[pyo3(signature = (dn, *, attributes))]
    fn add(&self, py: Python<'_>, dn: &str, attributes: &Bound<'_, PyDict>) -> PyResult<()> {
        if attributes.is_empty() {
            return Err(PyValueError::new_err("add requires at least one attribute"));
        }
        let mut attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = Vec::new();
        for (key, values) in attributes.iter() {
            let attr: String = key.extract()?;
            let list: Vec<Py<PyAny>> = values.extract()?;
            let set = values_to_set(py, list)?;
            if set.is_empty() {
                return Err(PyValueError::new_err(format!(
                    "add of {attr} requires at least one value"
                )));
            }
            attrs.push((attr.into_bytes(), set));
        }

        self.with_conn(py, |conn| {
            let result = conn
                .add(dn, attrs)
                .map_err(|e| OpError::Failed(e.to_string()))?;
            if result.rc != 0 {
                return Err(OpError::Result(result.rc, result.text));
            }
            Ok(())
        })
        .map_err(|e| e.into_pyerr("Add"))
    }

    /// Deletes an entry (the children, if any, must be deleted first).
    fn delete(&self, py: Python<'_>, dn: &str) -> PyResult<()> {
        self.with_conn(py, |conn| {
            let result = conn
                .delete(dn)
                .map_err(|e| OpError::Failed(e.to_string()))?;
            if result.rc != 0 {
                return Err(OpError::Result(result.rc, result.text));
            }
            Ok(())
        })
        .map_err(|e| e.into_pyerr("Delete"))
    }

    /// Performs a modify operation. `changes` maps attribute names to a
    /// list of `(operation, values)` tuples, where operation is one of
    /// `"add"`, `"delete"`, `"replace"` or `"increment"`, and values is a
    /// list of `str` or `bytes`.
    #[pyo3(signature = (dn, *, changes))]
    fn modify(&self, py: Python<'_>, dn: &str, changes: &Bound<'_, PyDict>) -> PyResult<()> {
        if changes.is_empty() {
            return Err(PyValueError::new_err("modify requires at least one change"));
        }
        let mods = parse_changes(py, changes)?;

        self.with_conn(py, |conn| {
            let result = conn
                .modify(dn, mods)
                .map_err(|e| OpError::Failed(e.to_string()))?;
            if result.rc != 0 {
                return Err(OpError::Result(result.rc, result.text));
            }
            Ok(())
        })
        .map_err(|e| e.into_pyerr("Modify"))
    }

    /// Closes the connection. Idempotent.
    fn unbind(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(move || {
            // Poison-tolerant: even after a previous panic the socket must
            // remain releasable.
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(mut conn) = guard.take() {
                if let Some(timeout) = self.op_timeout {
                    conn.with_timeout(timeout);
                }
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| conn.unbind())) {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(LdapError::new_err(format!("Unbind operation failed: {e}"))),
                    Err(_) => Err(LdapError::new_err(
                        "Unbind operation failed: the LDAP library panicked",
                    )),
                }
            } else {
                Ok(())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_depth_counts_nesting() {
        assert_eq!(filter_max_depth("(a=b)"), 1);
        assert_eq!(filter_max_depth("(&(a=b)(|(c=d)(e=f)))"), 3);
        assert_eq!(filter_max_depth(""), 0);
    }

    #[test]
    fn test_filter_depth_honours_escapes() {
        // Escaped parentheses do not open or close groups.
        assert_eq!(filter_max_depth(r"(cn=a\28b\29)"), 1);
        assert_eq!(filter_max_depth(r"(cn=a\(b)"), 1);
        // A backslash escapes the next character, whatever it is.
        assert_eq!(filter_max_depth(r"(cn=a\\)(cn=b)"), 1);
    }

    #[test]
    fn test_filter_depth_unbalanced_does_not_panic() {
        assert_eq!(filter_max_depth("((("), 3);
        assert_eq!(filter_max_depth(")))"), 0);
    }

    #[test]
    fn test_parse_timeout_valid() {
        assert_eq!(parse_timeout(0.0).expect("zero"), None);
        assert_eq!(parse_timeout(-1.0).expect("negative"), None);
        assert_eq!(
            parse_timeout(2.5).expect("valid"),
            Some(Duration::from_millis(2500))
        );
    }

    #[test]
    fn test_parse_timeout_rejects_non_finite() {
        assert!(parse_timeout(f64::INFINITY).is_err());
        assert!(parse_timeout(f64::NAN).is_err());
        assert!(parse_timeout(f64::MAX).is_err());
    }
}
