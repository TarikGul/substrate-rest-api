mod routes;

use axum::{routing::get, Router};
use routes::blocks::{get_latest_block, AppState};
use std::sync::Arc;
use subxt::{OnlineClient, PolkadotConfig};
use tracing_subscriber;

#[tokio::main]
async fn main() {
    // Initialize tracing for logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    // Specify the WebSocket URL of the Substrate node
    let ws_url = "ws://127.0.0.1:9944";

    // Log the WebSocket connection
    tracing::info!("Connecting to Substrate node at {}", ws_url);

    // Create a new Subxt client to connect to the specified Substrate node
    let client = OnlineClient::<PolkadotConfig>::from_url(ws_url)
        .await
        .expect("Failed to connect to the node");

    // Log successful connection
    tracing::info!("Successfully connected to Substrate node");

    let state = AppState {
        client: Arc::new(client),
    };

    // Define the server address
    let addr = "127.0.0.1:3000".parse().unwrap();

    // Log server initialization details
    tracing::info!("Starting server on http://{}", addr);

    // Define routes
    let app = Router::new()
        .route("/blocks/latest", get(get_latest_block))
        .with_state(state);

    // Start the server
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .expect("Server crashed");

    // Log server termination (if any)
    tracing::info!("Server stopped");
}
