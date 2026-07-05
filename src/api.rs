use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::cache::SnapshotStore;
use crate::config::Config;
use crate::exporter::prometheus;

#[derive(Clone)]
pub struct ApiState {
    store: SnapshotStore,
}

pub async fn serve(config: &Config, store: SnapshotStore) -> Result<()> {
    let state = ApiState { store };
    let metrics_path = config.metrics_path.clone();
    let app = Router::new()
        .route(&metrics_path, get(metrics_handler))
        .route("/-/health", get(health_handler))
        .route("/-/ready", get(ready_handler))
        .with_state(state);

    let listener = TcpListener::bind(config.listen_address)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_address))?;
    info!(address = %config.listen_address, metrics_path = %metrics_path, "storage harvester listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;

    Ok(())
}

async fn metrics_handler(State(state): State<ApiState>) -> Response {
    let snapshots = state.store.snapshots().await;
    let body = prometheus::render(&snapshots);
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn ready_handler(State(state): State<ApiState>) -> impl IntoResponse {
    if state.store.ready().await {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "initial scans pending\n")
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(%error, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => error!(%error, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}
