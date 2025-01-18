use axum::{extract::State, response::Json};
use hex;
use serde::Serialize;
use std::sync::Arc;
use subxt::config::substrate::DigestItem;
use subxt::config::substrate::H256;
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
    pub number: String,
    pub parent_hash: H256,
    pub state_root: H256,
    pub extrinsics_root: H256,
    pub logs: Vec<LogEntry>,
    pub extrinsics: Vec<ExtrinsicInfo>,
}

#[derive(Debug, Serialize)]
pub struct LogEntry {
    log_type: String,
    index: String,
    value: Vec<String>,
}

pub async fn get_latest_block(State(state): State<AppState>) -> Json<BlockResponse> {
    let client = &state.client;

    // Fetch the latest block
    let block = client
        .blocks()
        .at_latest()
        .await
        .expect("Failed to fetch the latest block");

    let block_number = block.header().number;
    let block_hash = block.hash();
    let state_root = block.header().state_root;
    let parent_hash = block.header().parent_hash;
    let extrinsics_root = block.header().extrinsics_root;
    let logs = transform_logs(&block.header().digest.logs);

    // Extract extrinsics
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

    // Return the block response as JSON
    Json(BlockResponse {
        hash: format!("{:?}", block_hash),
        number: block_number.to_string(),
        state_root,
        parent_hash,
        extrinsics_root,
        logs,
        extrinsics,
    })
}

pub fn transform_logs(logs: &[DigestItem]) -> Vec<LogEntry> {
    logs.iter()
        .enumerate()
        .map(|(index, log)| {
            match log {
                DigestItem::PreRuntime(engine_id, data) => LogEntry {
                    log_type: "PreRuntime".to_string(),
                    index: index.to_string(),
                    value: vec![
                        format!("0x{}", hex::encode(engine_id)), // EngineId as hex
                        format!("0x{}", hex::encode(data)),      // Data as hex
                    ],
                },
                DigestItem::Consensus(engine_id, data) => LogEntry {
                    log_type: "Consensus".to_string(),
                    index: index.to_string(),
                    value: vec![
                        format!("0x{}", hex::encode(engine_id)), // EngineId as hex
                        format!("0x{}", hex::encode(data)),      // Data as hex
                    ],
                },
                DigestItem::Seal(engine_id, data) => LogEntry {
                    log_type: "Seal".to_string(),
                    index: index.to_string(),
                    value: vec![
                        format!("0x{}", hex::encode(engine_id)), // EngineId as hex
                        format!("0x{}", hex::encode(data)),      // Data as hex
                    ],
                },
                DigestItem::Other(data) => LogEntry {
                    log_type: "Other".to_string(),
                    index: index.to_string(),
                    value: vec![
                        format!("0x{}", hex::encode(data)), // Data as hex
                    ],
                },
                DigestItem::RuntimeEnvironmentUpdated => LogEntry {
                    log_type: "RuntimeEnvironmentUpdated".to_string(),
                    index: index.to_string(),
                    value: vec![], // No associated data
                },
            }
        })
        .collect()
}
