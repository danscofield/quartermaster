// Logging, recovery, request ID (tower layers)

use axum::Router;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

const X_REQUEST_ID: &str = "x-request-id";

/// Applies standard middleware layers to the router:
/// - Request ID generation and propagation
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
            .layer(PropagateRequestIdLayer::new(x_request_id))
            .layer(TraceLayer::new_for_http())
            .layer(CatchPanicLayer::new()),
    )
}
