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
//! Selection of cipher suites for rustls from OpenSSL-style cipher lists.
//!
//! UDS exposes an OpenSSL-style cipher list (`SECURE_CIPHERS`) in its
//! configuration. rustls cannot interpret those names directly, so this
//! module translates them to the rustls IANA names supported by the
//! `aws-lc-rs` provider and builds a [`CryptoProvider`] restricted to the
//! requested suites.
//!
//! Semantics differ from the OpenSSL backend on purpose:
//!
//! * An explicitly configured list that yields **no** valid suite is an
//!   error (fail-fast, matching `ssl.SSLContext.set_ciphers` behaviour),
//!   not a silent fallback to defaults.
//! * Unknown names in a list with at least one valid suite are skipped
//!   with a warning.
//! * No list configured means rustls defaults.
//!
//! DHE suites are not translated: rustls does not implement them.

use rustls::{
    SupportedCipherSuite,
    crypto::{CryptoProvider, aws_lc_rs},
};
use thiserror::Error;

/// Errors produced while configuring TLS for the LDAP connection.
#[derive(Debug, Error)]
pub enum TlsConfigError {
    /// The configured list did not yield a single supported cipher suite.
    #[error("no supported cipher suites found in {0:?}")]
    NoValidCiphers(String),

    /// TLS 1.0 and 1.1 are not supported by the rustls backend.
    #[error("unsupported minimum TLS version {0:?} (rustls supports 1.2 and 1.3)")]
    UnsupportedVersion(String),

    /// Could not build the certificate authority store.
    #[error("invalid CA certificate store: {0}")]
    RootStore(String),
}

/// Maps an OpenSSL cipher suite name to the equivalent rustls suite.
fn openssl_to_rustls_cipher_suite(cipher: &str) -> Option<SupportedCipherSuite> {
    let rust_cipher_name = match cipher {
        // TLS 1.3 suites
        "TLS_AES_256_GCM_SHA384" => Some("TLS13_AES_256_GCM_SHA384"),
        "TLS_AES_128_GCM_SHA256" => Some("TLS13_AES_128_GCM_SHA256"),
        "TLS_CHACHA20_POLY1305_SHA256" => Some("TLS13_CHACHA20_POLY1305_SHA256"),

        // TLS 1.2 suites
        "ECDHE-ECDSA-AES256-GCM-SHA384" => Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
        "ECDHE-ECDSA-AES128-GCM-SHA256" => Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        "ECDHE-ECDSA-CHACHA20-POLY1305-SHA256" => {
            Some("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")
        }
        "ECDHE-RSA-AES256-GCM-SHA384" => Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        "ECDHE-RSA-AES128-GCM-SHA256" => Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        "ECDHE-RSA-CHACHA20-POLY1305-SHA256" => Some("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),

        // Unknown suite
        _ => None,
    }?;

    rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES
        .iter()
        .find(|suite| suite.suite().as_str() == Some(rust_cipher_name))
        .copied()
}

/// Builds a [`CryptoProvider`] from an optional OpenSSL-style cipher list.
///
/// `None` (or an empty/whitespace-only list) selects the rustls defaults.
/// An explicitly configured list must yield at least one supported suite,
/// otherwise [`TlsConfigError::NoValidCiphers`] is returned.
pub fn provider(ciphers: Option<&str>) -> Result<CryptoProvider, TlsConfigError> {
    let Some(list) = ciphers.filter(|c| !c.trim().is_empty()) else {
        log::debug!("No cipher list configured, using rustls defaults");
        return Ok(aws_lc_rs::default_provider());
    };

    let mut suites: Vec<SupportedCipherSuite> = Vec::new();
    for name in list.split(':') {
        match openssl_to_rustls_cipher_suite(name) {
            Some(suite) => suites.push(suite),
            None => log::warn!("Skipping unknown cipher suite: {name}"),
        }
    }

    if suites.is_empty() {
        return Err(TlsConfigError::NoValidCiphers(list.to_owned()));
    }

    log::debug!("Cipher suites: {suites:?}");
    Ok(CryptoProvider {
        cipher_suites: suites,
        ..aws_lc_rs::default_provider()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_len() -> usize {
        aws_lc_rs::default_provider().cipher_suites.len()
    }

    #[test]
    fn test_none_uses_defaults() {
        let result = provider(None).expect("should use defaults");
        assert_eq!(result.cipher_suites.len(), default_len());
    }

    #[test]
    fn test_empty_list_uses_defaults() {
        let result = provider(Some("")).expect("empty list means defaults");
        assert_eq!(result.cipher_suites.len(), default_len());
    }

    #[test]
    fn test_invalid_list_fails() {
        let result = provider(Some(
            "ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512",
        ));
        assert!(matches!(result, Err(TlsConfigError::NoValidCiphers(_))));
    }

    #[test]
    fn test_mixed_list_filters_valid_ones() {
        let result = provider(Some(
            "ECDHE-RSA-AES256-GCM-SHA512:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305-SHA256",
        ))
        .expect("list has valid suites");
        assert_eq!(result.cipher_suites.len(), 2);
    }

    #[test]
    fn test_valid_tls13_list() {
        let result = provider(Some(
            "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
        ))
        .expect("all TLS 1.3 suites are supported");
        assert_eq!(result.cipher_suites.len(), 3);
    }
}
