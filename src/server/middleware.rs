// Logging, recovery, request ID (tower layers)

use axum::Router;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

const X_REQUEST_ID: &str = "x-request-id";

/// A type-safe wrapper around the request ID string.
///
/// Inserted into request extensions by the `inject_request_id` middleware so
/// handlers can extract it via `Extension<RequestId>`.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Newtype for an optional client certificate extracted from the TLS session.
///
/// Contains DER-encoded certificate bytes when a client presented a certificate
/// during the TLS handshake, or `None` when no TLS is configured or no client
/// certificate was presented.
///
/// Inserted into request extensions by the `inject_client_certificate` middleware,
/// accessible by handlers via `Extension<ClientCertificate>`.
#[derive(Clone, Debug)]
pub struct ClientCertificate(pub Option<Vec<u8>>);

/// Middleware function that reads the `x-request-id` header (set by
/// `SetRequestIdLayer`) and inserts a [`RequestId`] into request extensions.
async fn inject_request_id(
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let id = req
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    req.extensions_mut().insert(RequestId(id));
    next.run(req).await
}

/// Middleware function that extracts the peer certificate from `tokio-rustls`
/// connection metadata and inserts a [`ClientCertificate`] into request extensions.
///
/// The TLS acceptor layer is expected to insert a [`PeerCertificates`] value into
/// request extensions when a client presents certificates during the TLS handshake.
/// This middleware reads that value and wraps the first certificate (the leaf/end-entity
/// cert) in a `ClientCertificate` newtype for downstream handlers.
///
/// When no TLS is configured or the client did not present a certificate,
/// `ClientCertificate(None)` is inserted.
async fn inject_client_certificate(
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let client_cert = req
        .extensions()
        .get::<PeerCertificates>()
        .and_then(|peer_certs| peer_certs.0.first().cloned());

    req.extensions_mut().insert(ClientCertificate(client_cert));
    next.run(req).await
}

/// Holds DER-encoded peer certificates from the TLS session.
///
/// This type is expected to be inserted into request extensions by the TLS
/// acceptor layer (e.g., when using `tokio-rustls`). The first element is
/// the leaf/end-entity certificate; subsequent elements are intermediate certs.
///
/// When no client certificate is presented during the TLS handshake, this
/// extension will not be present in the request.
#[derive(Clone, Debug)]
pub struct PeerCertificates(pub Vec<Vec<u8>>);

/// Applies standard middleware layers to the router:
/// - Request ID generation and propagation
/// - Request ID injection into extensions (for type-safe extraction)
/// - Client certificate extraction from TLS connection metadata
/// - Tracing (structured request/response logging)
/// - Panic recovery (returns 500 instead of dropping the connection)
pub fn apply_middleware<S: Clone + Send + Sync + 'static>(router: Router<S>) -> Router<S> {
    let x_request_id = axum::http::HeaderName::from_static(X_REQUEST_ID);

    router.layer(
        ServiceBuilder::new()
            .layer(SetRequestIdLayer::new(
                x_request_id.clone(),
                MakeRequestUuid,
            ))
            .layer(axum::middleware::from_fn(inject_request_id))
            .layer(axum::middleware::from_fn(inject_client_certificate))
            .layer(PropagateRequestIdLayer::new(x_request_id))
            .layer(TraceLayer::new_for_http())
            .layer(CatchPanicLayer::new()),
    )
}
