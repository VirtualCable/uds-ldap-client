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
//! Construction of rustls client configurations for the LDAP connections.

use std::sync::Arc;

use rustls::{
    ClientConfig, RootCertStore,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
    version::{TLS12, TLS13},
};
use thiserror::Error;

use super::crypto_provider::{self, TlsConfigError};

/// Verifier that accepts any server certificate (the `verify_ssl=False`
/// path of the UDS configuration).
#[derive(Debug)]
struct NoCertVerification;

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Error variants of [`client_config`] beyond the cipher-list ones.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Could not build the certificate authority store.
    #[error(transparent)]
    Tls(#[from] TlsConfigError),
}

/// Builds the client configuration used to establish the TLS session of an
/// LDAP connection.
///
/// * `ciphers`: OpenSSL-style cipher list (`SECURE_CIPHERS`), or `None`.
/// * `min_tls_version`: `None`, `"1.2"` or `"1.3"` (`SECURE_MIN_TLS_VERSION`).
///   Defaults to TLS 1.2, matching the UDS server settings.
/// * `ca_certs_pem`: PEM-encoded CA certificates to trust
///   (`certificate_data`), or `None` to use the system store.
/// * `verify_ssl`: when `false`, disables certificate verification
///   (`verify_ssl=False` in the UDS configuration).
/// * `client_cert_pem`/`client_key_pem`: PEM-encoded client certificate and
///   key for mutual TLS, or `None`. Both must be provided together.
pub fn client_config(
    ciphers: Option<&str>,
    min_tls_version: Option<&str>,
    ca_certs_pem: Option<&[u8]>,
    verify_ssl: bool,
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> Result<Arc<ClientConfig>, ConfigError> {
    let provider: CryptoProvider = crypto_provider::provider(ciphers)?;

    let versions: &[&rustls::SupportedProtocolVersion] =
        match min_tls_version.map(str::trim).filter(|v| !v.is_empty()) {
            None | Some("1.2") => &[&TLS12, &TLS13],
            Some("1.3") => &[&TLS13],
            Some(other) => return Err(TlsConfigError::UnsupportedVersion(other.to_owned()).into()),
        };

    let roots = root_store(ca_certs_pem, verify_ssl)?;

    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(|e| TlsConfigError::RootStore(format!("unsupported protocol versions: {e}")))?
        .with_root_certificates(roots);

    let mut config = match (client_cert_pem, client_key_pem) {
        (Some(cert_pem), Some(key_pem)) => builder
            .with_client_auth_cert(client_certificates(cert_pem)?, private_key(key_pem)?)
            .map_err(|e| {
                TlsConfigError::RootStore(format!("invalid client certificate/key pair: {e}"))
            })?,
        (None, None) => builder.with_no_client_auth(),
        (Some(_), None) | (None, Some(_)) => {
            return Err(TlsConfigError::RootStore(
                "client certificate and key must be provided together".to_owned(),
            )
            .into());
        }
    };

    if !verify_ssl {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertVerification));
    }

    Ok(Arc::new(config))
}

/// Builds the root certificate store: the provided PEM data when given,
/// the system store otherwise.
fn root_store(
    ca_certs_pem: Option<&[u8]>,
    verify_ssl: bool,
) -> Result<RootCertStore, TlsConfigError> {
    let mut store = RootCertStore::empty();
    match ca_certs_pem {
        Some(pem) => {
            for cert in CertificateDer::pem_slice_iter(pem) {
                let cert = cert.map_err(|e| {
                    TlsConfigError::RootStore(format!("invalid PEM certificate: {e}"))
                })?;
                store
                    .add(cert)
                    .map_err(|e| TlsConfigError::RootStore(format!("invalid certificate: {e}")))?;
            }
        }
        None => {
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = store.add(cert);
            }
        }
    }

    if store.is_empty() && verify_ssl {
        return Err(TlsConfigError::RootStore(
            "no CA certificates available to verify the server".to_owned(),
        ));
    }
    Ok(store)
}

/// Parses the client certificate chain from its PEM data.
fn client_certificates(cert_pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| TlsConfigError::RootStore(format!("invalid client certificate PEM: {e}")))?;
    if certs.is_empty() {
        return Err(TlsConfigError::RootStore(
            "no client certificate found in the PEM data".to_owned(),
        ));
    }
    Ok(certs)
}

/// Parses the client private key from its PEM data.
fn private_key(key_pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsConfigError> {
    PrivateKeyDer::pem_slice_iter(key_pem)
        .next()
        .ok_or_else(|| {
            TlsConfigError::RootStore("no private key found in the PEM data".to_owned())
        })?
        .map_err(|e| TlsConfigError::RootStore(format!("invalid private key PEM: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CLIENT_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIUdIyNSbxEawVfhC539y2T3+kp7aAwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIdWRzLXRlc3QwHhcNMjYxMTIxMTcxNzQ4WhcNMzYxMTE4
MTcxNzQ4WjATMREwDwYDVQQDDAh1ZHMtdGVzdDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAM0FO/0Lmay+6utfVq5kU1IPiBipIGboFZlsQO5qvVUiusNH
cw4UokJ3naxccR4zRbfQ95YZNxNftguPNu8yIZj4M6wjpMPRxp3Ome+VywErSbW4
oGu94gkcCCsOGdwPnsA3aWs9hZ2YF4t14sJIf+60QsK/Dcn6VRKLGIzp1C9lfT27
BPR35MyEKA20Tl7tHLld15J5F8EUHV4KHJXoFyqvYOelibUkUiT8kTZjmFfp4gny
8K2CAh+9Gr29KfdrA5lPtA97MFEKV4NUJFdvMarYpwcsaomFcUYxg9ZlHPkMBqIj
twxdwhnVZk93O/rK72a935spYll9wvz386j6Sn0CAwEAAaNTMFEwHQYDVR0OBBYE
FPvozfXoEYRT7lTfar+W4d0bCJvfMB8GA1UdIwQYMBaAFPvozfXoEYRT7lTfar+W
4d0bCJvfMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADLcPCOH
w3jZzTs1HFwoSiT2T38KCJcA7s6t0Sxt5qDo48WC1T59GVEZdoTtiSlgPCgADYGO
9asmUNL/I9QODaqIecO8Pf5GXOBIgSPqxBMMmhiPV++13M4f2tO+b1ng6Mfy3rhE
/R63SJ6Um5TH5e3FzBC25YZ6FelQcfq1/kuuvWvcO1INI7O6/ZgQRMPjs5enrBJR
y0UCbYq77qYCvTlqSxVoktrrvqFn04u7rMzf126fgSyyebs/BziPlHZhptJFR+Z3
a/1se3aOS+0g7xRDyS/RLJN1zPmxXLiLuJPdfbwDGBvq3tz18QVDFE4QQeO9gkC2
xjX9/+bxP2r2vcU=
-----END CERTIFICATE-----
"#;
    const TEST_CLIENT_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNBTv9C5msvurr
X1auZFNSD4gYqSBm6BWZbEDuar1VIrrDR3MOFKJCd52sXHEeM0W30PeWGTcTX7YL
jzbvMiGY+DOsI6TD0cadzpnvlcsBK0m1uKBrveIJHAgrDhncD57AN2lrPYWdmBeL
deLCSH/utELCvw3J+lUSixiM6dQvZX09uwT0d+TMhCgNtE5e7Ry5XdeSeRfBFB1e
ChyV6Bcqr2DnpYm1JFIk/JE2Y5hX6eIJ8vCtggIfvRq9vSn3awOZT7QPezBRCleD
VCRXbzGq2KcHLGqJhXFGMYPWZRz5DAaiI7cMXcIZ1WZPdzv6yu9mvd+bKWJZfcL8
9/Oo+kp9AgMBAAECggEAAvk09gYRjAJW2OQQl0XoOXP1NtpZGHT8PzXlOS/+H/p5
d/SU1BrzgYBHnqTWlSgMNk7HEHu8I0FLnB5PHyf8ecH7yd7YeGiV91r0O5fSEmnE
z2hmlzlxSk2IRsuVD26AkGwdUMtbIT5/9OtYRxYTGOyvXTC1K/0/951h1UVc6PUK
trkqbleHdTeOuonVbGMNbcvwWsuin/imiGwrlS+LFP1qsUlIbO3dzx7IFcmonp9W
cEUxkyw5aXN1eKnQtp/fwmdmB5E/XOgHZ1QlR3PuDti/5+EOWf60HCeovuKGg47K
GYifH8m+1ryzLQrFGt1PxZ21xfmvucrxn7eDKOLKxwKBgQDq1ZvSARKdUML2AhQi
YEFmd0/HUHrpNydT6WF2iD+HzDWBKqhBo5ckiblXR9wiIu8Z16sO9uAXdFxzzrWN
a8FQrteUZraPWhELwoytjRK+3KHY/mRxIFR1wFOovRq2/Tsw31FuqwBbn3TTtBec
IuSDpWp6GWmUUlXWepUojzFEbwKBgQDff7iKwDu4q9OGUgoHk1k2GL+DMww1YMcU
T2+u+ufqZPC8IbnkOVV/N7hUk7LZYUvVokmKFPPny1QDr4ZdicEHAdvLXhaou+J0
MPFQ7D2bZnA9O9RvokZdu4aefLxaYUWuwWpHMVL/MaWuA3wiTGibLVUtTRsN3X+d
JdVtZo7N0wKBgQDRFOqtKYNXSYar3eHrUWQpROVlAkTMy+xaC5pZHKnj0G96124D
MxHo2C6KhVJ7mjrj+V817ZxLhbCi81I13dC6c1FBscmtDHXM0KTMCKS+BlabirQG
/M/2HwzdWbElZ4WB1/L644loCirMKrYyr+ZhR6/rkiCsjDocwft3pzYoRQKBgEY8
Cc84l8vx21gjodk9mdRhNJXTTevcTNN6Hxu653SGYgyNALDSv6Zp6ThS7epYJA+v
nzKQYRGfmPhLiYsNhiZglCS1naNK3+ApnTwT8UxLhcwIaDrooPpFuwlFI5+3X8GK
MI7M1ksx2+HyYGka3+ib9190EqNpzvegcxCdIRVXAoGASZqvJWJ7bkpVbKfwTYaC
P/32FTbrFLVT0DKP2cBp04z7tUtEN/5BhIRD2r2kytQLa0saPEKFICpU7aPV2xr6
fEWXmNMXYUnocFZVeTcNBt3vDzch36oG2ze8Gy+v9kTXqgk2ctqSdu0MIS/+x9oI
6T7C7DHWThhkZFDTlmVvKkQ=
-----END PRIVATE KEY-----
"#;

    #[test]
    fn test_client_cert_and_key_builds() {
        let config = client_config(
            None,
            None,
            None,
            true,
            Some(TEST_CLIENT_CERT.as_bytes()),
            Some(TEST_CLIENT_KEY.as_bytes()),
        );
        assert!(config.is_ok());
    }

    #[test]
    fn test_client_cert_without_key_fails() {
        let result = client_config(
            None,
            None,
            None,
            true,
            Some(TEST_CLIENT_CERT.as_bytes()),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_client_key_without_cert_fails() {
        let result = client_config(
            None,
            None,
            None,
            true,
            None,
            Some(TEST_CLIENT_KEY.as_bytes()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_client_cert_fails() {
        let result = client_config(
            None,
            None,
            None,
            true,
            Some(b"not a pem"),
            Some(TEST_CLIENT_KEY.as_bytes()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_no_client_cert_keeps_plain_path() {
        let config = client_config(None, None, None, true, None, None).expect("plain path");
        // Nothing to assert beyond construction: the dangerous verifier is
        // not installed when verify_ssl is true.
        let _ = config;
    }
}
