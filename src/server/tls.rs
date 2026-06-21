// TLS acceptor setup for permissive mTLS

use std::fs;
use std::io::BufReader;
use std::sync::Arc;

use rustls::server::danger::ClientCertVerified;
use rustls::SignatureScheme;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};

use crate::config::TlsConfig;

/// A permissive client certificate verifier that:
/// - Sends CertificateRequest to solicit client certs
/// - Always returns Ok from verify_client_cert (no TLS-layer rejection)
/// - Passes raw certificate bytes through for application-layer validation
///
/// All actual client certificate validation is deferred to the application
/// layer (`MtlsValidator`), enabling trust bundle rotation without server
/// restart and graceful fallback when no valid cert is presented.
#[derive(Debug)]
pub(crate) struct PermissiveClientCertVerifier {
    /// Supported signature verification schemes (required by rustls).
    supported_schemes: Vec<SignatureScheme>,
}

impl PermissiveClientCertVerifier {
    /// Creates a new `PermissiveClientCertVerifier` using the default
    /// crypto provider's supported signature verification algorithms.
    pub fn new() -> Self {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let supported_schemes = provider
            .signature_verification_algorithms
            .supported_schemes();
        Self { supported_schemes }
    }
}

impl rustls::server::danger::ClientCertVerifier for PermissiveClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_schemes.clone()
    }
}

/// Errors that can occur during TLS configuration setup.
#[derive(Debug)]
pub enum TlsSetupError {
    /// The certificate or key file could not be read from disk.
    FileNotFound { path: String, source: std::io::Error },
    /// The PEM-encoded certificate file could not be parsed.
    CertParseError(String),
    /// The PEM-encoded private key file could not be parsed.
    KeyParseError(String),
    /// rustls rejected the configuration.
    RustlsError(rustls::Error),
    /// The client verifier builder failed.
    VerifierBuilderError(String),
}

impl std::fmt::Display for TlsSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsSetupError::FileNotFound { path, source } => {
                write!(f, "TLS file not found '{}': {}", path, source)
            }
            TlsSetupError::CertParseError(msg) => {
                write!(f, "TLS certificate parse error: {}", msg)
            }
            TlsSetupError::KeyParseError(msg) => {
                write!(f, "TLS private key parse error: {}", msg)
            }
            TlsSetupError::RustlsError(e) => {
                write!(f, "rustls configuration error: {}", e)
            }
            TlsSetupError::VerifierBuilderError(msg) => {
                write!(f, "client verifier builder error: {}", msg)
            }
        }
    }
}

impl std::error::Error for TlsSetupError {}

/// Builds a `rustls::ServerConfig` with permissive client certificate handling.
///
/// The TLS layer is configured to:
/// - Present the server certificate and key for TLS termination
/// - Accept connections with or without client certificates (permissive)
/// - Never reject connections based on client certificate validity
/// - Pass raw client certificate bytes to the application layer for validation
///
/// All client certificate verification is deferred to the application layer
/// (`MtlsValidator`), keeping the TLS handshake simple and avoiding restarts
/// when trust bundles change.
pub fn build_tls_config(tls_config: &TlsConfig) -> Result<ServerConfig, TlsSetupError> {
    // Load server certificate chain from PEM file
    let cert_file = fs::File::open(&tls_config.cert_path).map_err(|e| {
        TlsSetupError::FileNotFound {
            path: tls_config.cert_path.clone(),
            source: e,
        }
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<_> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsSetupError::CertParseError(e.to_string()))?;

    if cert_chain.is_empty() {
        return Err(TlsSetupError::CertParseError(
            "no certificates found in PEM file".to_string(),
        ));
    }

    // Load private key from PEM file
    let key_file = fs::File::open(&tls_config.key_path).map_err(|e| {
        TlsSetupError::FileNotFound {
            path: tls_config.key_path.clone(),
            source: e,
        }
    })?;
    let mut key_reader = BufReader::new(key_file);
    let private_key = private_key(&mut key_reader)
        .map_err(|e| TlsSetupError::KeyParseError(e.to_string()))?
        .ok_or_else(|| {
            TlsSetupError::KeyParseError("no private key found in PEM file".to_string())
        })?;

    // Build a permissive client cert verifier:
    // - Sends CertificateRequest to solicit client certs
    // - Never rejects connections based on client cert validity
    // - All actual cert validation is deferred to the application layer
    let client_verifier = Arc::new(PermissiveClientCertVerifier::new());

    // Build the server config with the permissive client verifier
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, private_key)
        .map_err(TlsSetupError::RustlsError)?;

    Ok(config)
}

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;

use super::middleware::PeerCertificates;

/// Runs an HTTP server over TLS, extracting client certificates from each connection
/// and injecting them as `PeerCertificates` into request extensions.
///
/// This function:
/// 1. Accepts TCP connections on the provided listener
/// 2. Performs TLS handshake using `tokio-rustls`
/// 3. Extracts peer certificates (if presented) from the TLS session
/// 4. Serves HTTP requests using the provided axum router, injecting `PeerCertificates`
///    into each request's extensions before routing
///
/// The function runs indefinitely, spawning a task for each accepted connection.
pub async fn serve_tls(listener: TcpListener, tls_config: Arc<ServerConfig>, router: axum::Router) {
    let tls_acceptor = TlsAcceptor::from(tls_config);

    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(error = %e, "failed to accept TCP connection");
                continue;
            }
        };

        let acceptor = tls_acceptor.clone();
        let app = router.clone();

        tokio::spawn(async move {
            // Perform TLS handshake
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::debug!(
                        remote_addr = %remote_addr,
                        error = %e,
                        "TLS handshake failed"
                    );
                    return;
                }
            };

            // Extract peer certificates from the TLS session
            let peer_certs: Option<Vec<Vec<u8>>> = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect());

            let peer_certificates = peer_certs
                .map(|certs| PeerCertificates(certs))
                .unwrap_or_else(|| PeerCertificates(vec![]));

            // Wrap the router in a service that injects PeerCertificates into each request
            let service =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let peer_certs = peer_certificates.clone();
                    let mut app = app.clone();
                    async move {
                        // Convert hyper::Request<Incoming> to axum-compatible request
                        let (parts, body) = req.into_parts();
                        let body = axum::body::Body::new(body);
                        let mut req = axum::http::Request::from_parts(parts, body);
                        req.extensions_mut().insert(peer_certs);
                        let response = app
                            .call(req)
                            .await
                            .unwrap_or_else(|err| match err {});
                        Ok::<_, std::io::Error>(response)
                    }
                });

            // Serve HTTP on the TLS stream
            let io = TokioIo::new(tls_stream);
            let builder = AutoBuilder::new(TokioExecutor::new());
            if let Err(e) = builder.serve_connection(io, service).await {
                tracing::debug!(
                    remote_addr = %remote_addr,
                    error = %e,
                    "connection error"
                );
            }
        });
    }
}
