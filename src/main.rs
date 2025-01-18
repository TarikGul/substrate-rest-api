mod routes;

use axum::{routing::get, Router};
use routes::blocks::{get_latest_block, AppState};
use std::sync::Arc;
use subxt::{OnlineClient, PolkadotConfig};
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing_subscriber;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Connect to the Substrate node
    let ws_url = "ws://127.0.0.1:9944";
    tracing::info!("Connecting to Substrate node at {}", ws_url);

    let client = OnlineClient::<PolkadotConfig>::from_url(ws_url)
        .await
        .expect("Failed to connect to the node");
    tracing::info!("Successfully connected to Substrate node");

    let state = AppState {
        client: Arc::new(client),
    };

    let addr = "127.0.0.1:3000".parse().unwrap();
    tracing::info!("Starting server on http://{}", addr);

    // Define the application
    let app = Router::new()
        .route("/blocks/latest", get(get_latest_block))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        ) // Logging middleware
        .with_state(state);

    // Start the server
    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .expect("Server crashed");

    tracing::info!("Server stopped");
}
