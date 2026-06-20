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

/// Applies standard middleware layers to the router:
/// - Request ID generation and propagation
/// - Request ID injection into extensions (for type-safe extraction)
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
            .layer(PropagateRequestIdLayer::new(x_request_id))
            .layer(TraceLayer::new_for_http())
            .layer(CatchPanicLayer::new()),
    )
}
