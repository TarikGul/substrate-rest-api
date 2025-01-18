use axum::{extract::State, response::Json};
use serde::Serialize;
use std::sync::Arc;
use subxt::{OnlineClient, PolkadotConfig};

#[derive(Clone)]
pub struct AppState {
    pub client: Arc<OnlineClient<PolkadotConfig>>,
}

#[derive(Serialize)]
pub struct ExtrinsicInfo {
    pub index: usize,
    pub pallet_name: String,
}

#[derive(Serialize)]
pub struct BlockResponse {
    pub hash: String,
    pub number: u32,
    pub extrinsics: Vec<ExtrinsicInfo>,
}

// Handler to fetch the latest block
pub async fn get_latest_block(State(state): State<AppState>) -> Json<BlockResponse> {
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
            pallet_name: ext
                .pallet_name()
                .map_or_else(|err| format!("Error: {}", err), |name| name.to_string()),
        })
        .collect::<Vec<_>>();

    // Create the response
    let response = BlockResponse {
        hash: format!("{:?}", block_hash),
        number: block_number,
        extrinsics,
    };

    // Return the response as JSON
    Json(response)
}
