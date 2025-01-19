use axum::{extract::State, response::Json};
use hex;
use serde::Serialize;
use std::sync::Arc;
use subxt::blocks::Extrinsics;
use subxt::config::substrate::{AccountId32, DigestItem, H256};
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
    pub author_id: Option<AccountId32>,
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

const AURA_ENGINE_ID: &[u8; 4] = b"aura";
const BABE_ENGINE_ID: &[u8; 4] = b"BABE";
const NIMBUS_ENGINE_ID: &[u8; 4] = b"nmbs";
const POW_ENGINE_ID: &[u8; 4] = b"pow_";

#[subxt::subxt(runtime_metadata_path = "./metadata.scale")]
pub mod polkadot {}

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
    let author_id = get_author_id(State(state), block_hash, &block.header().digest.logs).await;

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
        author_id,
        logs,
        extrinsics,
    })
}

pub async fn get_author_id(
    State(state): State<AppState>,
    hash: H256,
    logs: &[DigestItem],
) -> Option<AccountId32> {
    let client = &state.client;
    let address = polkadot::storage().session().validators();
    let validators = client.storage().at(hash).fetch(&address).await.unwrap();

    extract_author(logs, &validators)
}

pub fn extract_author(
    logs: &[DigestItem],
    validators: &Option<Vec<AccountId32>>,
) -> Option<AccountId32> {
    let validators = validators.as_ref()?; // Safely unwrap the Option

    // Process PreRuntime logs first
    if let Some(DigestItem::PreRuntime(engine_id, data)) = logs
        .iter()
        .find(|log| matches!(log, DigestItem::PreRuntime(_, _)))
    {
        if let Some(author) = extract_author_from_engine(engine_id, data, validators) {
            return Some(author);
        }
    }

    // Process Consensus logs
    if let Some(DigestItem::Consensus(engine_id, data)) = logs
        .iter()
        .find(|log| matches!(log, DigestItem::Consensus(_, _)))
    {
        if let Some(author) = extract_author_from_engine(engine_id, data, validators) {
            return Some(author);
        }
    }

    // Process Seal logs
    if let Some(DigestItem::Seal(engine_id, data)) = logs
        .iter()
        .find(|log| matches!(log, DigestItem::Seal(_, _)))
    {
        if let Some(author) = extract_author_from_engine(engine_id, data, validators) {
            return Some(author);
        }
    }

    None
}

/// Extract the author based on the consensus engine.
///
/// # Arguments
///
/// - `engine_id`: The consensus engine ID.
/// - `data`: The data associated with the digest item.
/// - `validators`: The session validators, if applicable.
///
/// # Returns
///
/// The account ID of the author, if it can be determined.
fn extract_author_from_engine(
    engine_id: &[u8; 4],
    data: &[u8],
    validators: &[AccountId32],
) -> Option<AccountId32> {
    tracing::info!("Processing engine: {:?}", engine_id);
    match engine_id {
        // Aura: Author is derived from slot number modulo validators
        AURA_ENGINE_ID => {
            let raw_slot_number: [u8; 8] = data.get(..8)?.try_into().ok()?;
            let slot_number = u64::from_le_bytes(raw_slot_number);
            let index = (slot_number as usize) % validators.len();
            Some(validators.get(index)?.clone())
        }
        // BABE: Author is determined by raw digest value
        BABE_ENGINE_ID => {
            let raw_slot_index: [u8; 4] = data.get(..4)?.try_into().ok()?;
            let slot_index = u32::from_le_bytes(raw_slot_index);
            validators.get(slot_index as usize).cloned()
        }
        // Nimbus & PoW: Author ID is stored directly in the digest data
        NIMBUS_ENGINE_ID | POW_ENGINE_ID => {
            let account_id: [u8; 32] = data.try_into().ok()?;
            Some(AccountId32::from(account_id))
        }
        // Unknown engine
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use subxt::config::substrate::{AccountId32, DigestItem};

    #[test]
    fn test_extract_author_aura() {
        let logs = vec![DigestItem::PreRuntime(
            *b"aura",
            vec![0, 0, 0, 0, 0, 0, 0, 1],
        )]; // Slot number = 1
        let validators = Some(vec![
            AccountId32::from([0; 32]),
            AccountId32::from([1; 32]),
            AccountId32::from([2; 32]),
        ]);

        let author = extract_author(&logs, &validators);

        assert_eq!(
            author,
            Some(AccountId32::from([1; 32])),
            "The author ID should be the validator corresponding to slot 1."
        );
    }

    #[test]
    fn test_extract_author_babe() {
        let logs = vec![DigestItem::PreRuntime(*b"BABE", vec![2, 0, 0, 0])]; // Slot index = 2
        let validators = Some(vec![
            AccountId32::from([0; 32]),
            AccountId32::from([1; 32]),
            AccountId32::from([2; 32]),
        ]);

        let author = extract_author(&logs, &validators);

        assert_eq!(
            author,
            Some(AccountId32::from([2; 32])),
            "The author ID should be the validator at index 2."
        );
    }

    #[test]
    fn test_extract_author_nimbus() {
        let logs = vec![DigestItem::Seal(*b"nmbs", [1; 32].to_vec())]; // Author ID directly in data
        let validators = Some(vec![
            AccountId32::from([0; 32]),
            AccountId32::from([1; 32]),
            AccountId32::from([2; 32]),
        ]);

        let author = extract_author(&logs, &validators);

        assert_eq!(
            author,
            Some(AccountId32::from([1; 32])),
            "The author ID should be extracted directly from the Seal digest."
        );
    }

    #[test]
    fn test_extract_author_no_validators() {
        let logs = vec![DigestItem::PreRuntime(*b"aura", vec![0; 8])]; // Slot number = 0
        let validators: Option<Vec<AccountId32>> = None; // No validators provided

        let author = extract_author(&logs, &validators);

        assert_eq!(author, None, "No validators should result in no author ID.");
    }

    #[test]
    fn test_extract_author_no_logs() {
        let logs: Vec<DigestItem> = vec![]; // No logs
        let validators = Some(vec![
            AccountId32::from([0; 32]),
            AccountId32::from([1; 32]),
            AccountId32::from([2; 32]),
        ]);

        let author = extract_author(&logs, &validators);

        assert_eq!(author, None, "No logs should result in no author ID.");
    }

    #[test]
    fn test_extract_author_invalid_slot_index() {
        let logs = vec![DigestItem::PreRuntime(*b"BABE", vec![255, 255, 255, 255])]; // Invalid slot index
        let validators = Some(vec![
            AccountId32::from([0; 32]),
            AccountId32::from([1; 32]),
            AccountId32::from([2; 32]),
        ]);

        let author = extract_author(&logs, &validators);

        assert_eq!(
            author, None,
            "An invalid slot index should result in no author ID."
        );
    }
}
