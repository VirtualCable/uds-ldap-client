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

use ldap3::{
    LdapConn, LdapConnSettings, Mod, ResultEntry, Scope, SearchEntry, SearchOptions,
    result::LdapError as RustLdapError,
};
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

/// Internal error of the blocking operations, so that exceptions are
/// materialised outside `py.allow_threads`.
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

/// Extracts the referral URIs from a failed operation result, if the
/// operation was a search answered with a referral.
fn referral_uris(e: &RustLdapError) -> Option<Vec<String>> {
    if let RustLdapError::LdapResult { result } = e
        && (result.rc == REFERRAL_CODE || !result.refs.is_empty())
    {
        return Some(result.refs.clone());
    }
    None
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
                    let first = set.into_iter().next().ok_or_else(|| {
                        PyValueError::new_err(format!(
                            "increment of {attr} requires exactly one value"
                        ))
                    })?;
                    Mod::Increment(name, first)
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
}

impl Connection {
    /// Runs a blocking operation against the stored connection with the
    /// GIL released. Exceptions are materialised outside the closure.
    fn with_conn<T: Send>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&mut LdapConn) -> Result<T, OpError> + Send,
    ) -> Result<T, OpError> {
        let mut guard = self.inner.lock().expect("LDAP connection mutex poisoned");
        let conn = guard
            .as_mut()
            .ok_or_else(|| OpError::Failed("connection is closed".to_owned()))?;
        py.detach(|| f(conn))
    }
}

#[pymethods]
impl Connection {
    /// Connects and performs a simple bind. A rejected bind raises
    /// `BindError`; any other failure raises `LdapError`.
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
        let scheme = if use_ssl { "ldaps" } else { "ldap" };
        let url = format!("{scheme}://{host}:{port}");

        let mut settings = LdapConnSettings::new();
        if let Some(seconds) = timeout.filter(|t| *t > 0.0) {
            settings = settings.set_conn_timeout(Duration::from_secs_f64(seconds));
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
            Connect(String),
            Bind(String),
        }

        // Blocking connect + bind with the GIL released.
        let conn = py
            .detach(|| -> Result<LdapConn, ConnectError> {
                let mut conn = LdapConn::with_settings(settings, &url)
                    .map_err(|e| ConnectError::Connect(format!("{host}:{port}: {e}")))?;
                if let Some(seconds) = timeout.filter(|t| *t > 0.0) {
                    // Parity with python-ldap3's receive_timeout: applies to
                    // every subsequent operation on this connection.
                    conn.with_timeout(Duration::from_secs_f64(seconds));
                }
                let result = conn
                    .simple_bind(&username, &password)
                    .map_err(|e| ConnectError::Bind(format!("{host}:{port}: {e}")))?;
                if result.rc != 0 {
                    // Surface the LDAP result message (e.g. AD
                    // "AcceptSecurityContext error, data 773, ...") so callers can
                    // distinguish an expired password from a generic auth failure.
                    let text = if result.text.is_empty() {
                        format!("result code {rc}", rc = result.rc)
                    } else {
                        result.text
                    };
                    return Err(ConnectError::Bind(format!(
                        "{host}:{port} as {username}: {text}"
                    )));
                }
                Ok(conn)
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

        let (raw_entries, referrals) = self
            .with_conn(py, |conn| {
                conn.with_search_options(SearchOptions::new().sizelimit(size_limit));
                let result = conn
                    .search(base, scope, filter, attrs)
                    .map_err(|e| OpError::Failed(e.to_string()))?;
                match result.success() {
                    Ok((entries, res)) => Ok((
                        entries.into_iter().map(search_entry_to_raw).collect(),
                        res.refs,
                    )),
                    Err(e) => {
                        if let Some(refs) = referral_uris(&e) {
                            return Ok((Vec::new(), refs));
                        }
                        Err(OpError::Failed(e.to_string()))
                    }
                }
            })
            .map_err(|e| e.into_pyerr("Search"))?;

        let response = PyDict::new(py);
        let entries = PyList::empty(py);
        for raw in raw_entries {
            let dict = PyDict::new(py);
            dict.set_item("dn", raw.dn)?;
            for (attr, values) in raw.attrs {
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
        let mut guard = self.inner.lock().expect("LDAP connection mutex poisoned");
        if let Some(mut conn) = guard.take() {
            py.detach(|| {
                conn.unbind()
                    .map_err(|e| LdapError::new_err(format!("Unbind operation failed: {e}")))
            })?;
        }
        Ok(())
    }
}
