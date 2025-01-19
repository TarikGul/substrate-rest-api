use axum::{extract::State, response::Json};
use hex;
use serde::Serialize;
use std::sync::Arc;
use subxt::blocks::Extrinsics;
use subxt::config::substrate::{DigestItem, H256};
use subxt::ext::scale_value::Composite;
use subxt::{OnlineClient, PolkadotConfig};

#[derive(Clone)]
pub struct AppState {
    pub client: Arc<OnlineClient<PolkadotConfig>>,
}

#[derive(Serialize)]
pub struct ExtrinsicInfo {
    pub method: ExtrinsicMethod,
    pub signature: Option<String>,
    pub nonce: Option<String>,
    pub tip: Option<String>,
    pub hash: H256,
    pub args: Option<Composite<u32>>,
    pub events: Vec<Composite<u32>>,
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

#[derive(Serialize)]
pub struct ExtrinsicMethod {
    pallet: String,
    method: String,
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

    let extrinsics = transform_extrinsics(extrinsics_data).await;

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

async fn transform_extrinsics(
    extrinsics: Extrinsics<PolkadotConfig, OnlineClient<PolkadotConfig>>,
) -> Vec<ExtrinsicInfo> {
    let mut result = Vec::new();

    for (_, extrinsic) in extrinsics.iter().enumerate() {
        let pallet = extrinsic.pallet_name().unwrap_or_else(|_| "Unknown");
        let method = extrinsic.variant_name().unwrap_or_else(|_| "Unknown");
        let hash = extrinsic.hash();
        let args = extrinsic.field_values().ok();
        let signature = extrinsic
            .signature_bytes()
            .map(|bytes| format!("0x{}", hex::encode(bytes)));

        let nonce = extrinsic
            .signed_extensions()
            .iter()
            .filter_map(|ext| ext.nonce())
            .next()
            .map(|nonce| nonce.to_string());

        let tip = extrinsic
            .signed_extensions()
            .iter()
            .filter_map(|ext| ext.tip())
            .next()
            .map(|tip| tip.to_string());

        // Fetch events asynchronously
        let events = extrinsic.events().await.unwrap();

        // Extract field values from events
        let event_info = events
            .iter()
            .filter_map(|event| {
                match event {
                    Ok(e) => e.field_values().ok(), // Extract field values if valid
                    Err(err) => {
                        tracing::error!("Error processing event: {:?}", err);
                        None
                    }
                }
            })
            .collect(); // Collect valid field values

        result.push(ExtrinsicInfo {
            method: ExtrinsicMethod {
                pallet: pallet.to_string(),
                method: method.to_string(),
            },
            signature,
            nonce,
            tip,
            hash,
            args,
            events: event_info, // Add events to ExtrinsicInfo
        });
    }

    result
}
