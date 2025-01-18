mod config;
mod routes;

use axum::{routing::get, Router};
use config::Config;
use routes::blocks::{get_latest_block, AppState};
use std::sync::Arc;
use subxt::{OnlineClient, PolkadotConfig};
use tower_http::trace::{self, TraceLayer};
use tracing_subscriber::fmt;

#[tokio::main]
async fn main() {
    let config = Config::from_env();
    // Initialize tracing
    fmt().with_max_level(config.log_level).init();

    // Connect to the Substrate node
    let ws_url = &config.ws_url;
    tracing::info!("Connecting to Substrate node at {}", ws_url);

    let client: OnlineClient<PolkadotConfig> = OnlineClient::<PolkadotConfig>::from_url(ws_url)
        .await
        .expect("Failed to connect to the node");
    tracing::info!("Successfully connected to Substrate node");

    let state = AppState {
        client: Arc::new(client),
    };

    let addr = format!("0.0.0.0:{}", config.app_port).parse().unwrap();
    tracing::info!("Starting server on http://{}", addr);

    let app = Router::new()
        .route("/blocks/latest", get(get_latest_block))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    trace::DefaultMakeSpan::new()
                        .level(config.log_level)
                        .include_headers(true),
                )
                .on_response(
                    trace::DefaultOnResponse::new()
                        .level(config.log_level)
                        .include_headers(true),
                ),
        )
        .with_state(state);

    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .expect("Server crashed");

    tracing::info!("Server stopped");
}
