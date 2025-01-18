use axum::{
    extract::State,
    response::Json,
    routing::get,
    Router,
};
use serde::Serialize;
use subxt::{OnlineClient, PolkadotConfig};
use std::sync::Arc;
use tracing_subscriber;

#[derive(Clone)]
struct AppState {
    client: Arc<OnlineClient<PolkadotConfig>>,
}

#[derive(Serialize)]
struct ExtrinsicInfo {
    index: usize,
    pallet_name: String,
}

#[derive(Serialize)]
struct BlockResponse {
    hash: String,
    number: u32,
    extrinsics: Vec<ExtrinsicInfo>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing for logging
    // Set up a default tracing subscriber with INFO level
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO) // Set the maximum log level
        .with_target(true) // Show target/module path in logs
        .with_thread_ids(true) // Show thread IDs for debugging (optional)
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

// Handler to fetch the latest block
async fn get_latest_block(
    State(state): State<AppState>,
) -> Json<BlockResponse> {
    let client = &state.client;

    // Use the `blocks()` API to fetch the latest block
    let block = client
        .blocks()
        .at_latest()
        .await
        .expect("Failed to fetch the latest block");

    let block_number = block.header().number;
    let block_hash = block.hash();

    // Extract and format individual extrinsics
    let extrinsics_data = block
        .extrinsics()
        .await
        .expect("Failed to fetch extrinsics");

    let extrinsics = extrinsics_data
        .iter()
        .enumerate()
        .map(|(index, ext)| ExtrinsicInfo {
            index,
            pallet_name: ext.pallet_name().map_or_else(|err| format!("Error: {}", err), |name| name.to_string()), 
        })
        .collect::<Vec<_>>();

    // Create the response
    let response = BlockResponse {
        hash: format!("{:?}", block_hash),
        number: block_number,
        extrinsics,
    };

    // Print the response as JSON to the console
    let json = serde_json::to_string_pretty(&response).expect("Failed to serialize to JSON");
    println!("{}", json);

    // Return the response as JSON
    Json(response)
}
