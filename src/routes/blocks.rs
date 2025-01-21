use axum::{extract::State, response::Json};
use hex;
use serde::Serialize;
use sp_consensus_babe::digests::PreDigest;
use std::sync::Arc;
use subxt::blocks::Extrinsics;
use subxt::config::substrate::ConsensusEngineId;
use subxt::config::substrate::{AccountId32, DigestItem, H256};
use subxt::ext::codec::Decode;
use subxt::ext::scale_value::{Composite, Primitive, Value, ValueDef};
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
    pub args: Option<serde_json::Value>,
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

fn is_aura(engine: ConsensusEngineId) -> bool {
    engine == [b'a', b'u', b'r', b'a']
}
fn is_babe(engine: ConsensusEngineId) -> bool {
    engine == [b'B', b'A', b'B', b'E']
}
fn is_pow(engine: ConsensusEngineId) -> bool {
    engine == [b'p', b'o', b'w', b'_']
}

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

    // Need help below with that error.
    let validators = match client
        .storage()
        .at(block_hash)
        .fetch(&polkadot::storage().session().validators())
        .await
    {
        Ok(Some(validators)) => validators, // Unwrap the Result and Option
        Ok(None) => vec![],                 // Default to an empty vector if no validators are found
        Err(_) => vec![],                   // Handle error gracefully (log or handle as needed)
    };
    let author_id = extract_author(&block.header().digest.logs, validators);

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

fn extract_author(
    digest_logs: &Vec<DigestItem>,
    validators: Vec<AccountId32>,
) -> Option<AccountId32> {
    // Process PreRuntime logs first
    if let Some(DigestItem::PreRuntime(engine, data)) = digest_logs
        .iter()
        .find(|item| matches!(item, DigestItem::PreRuntime(..)))
    {
        if is_babe(*engine) {
            let mut data: &[u8] = data;

            // Decode the PreDigest from the data, handling potential failures
            let pre_digest = PreDigest::decode(&mut data).ok()?;
            let authority_index = match pre_digest {
                PreDigest::Primary(primary) => primary.authority_index,
                PreDigest::SecondaryPlain(secondary) => secondary.authority_index,
                PreDigest::SecondaryVRF(secondary) => secondary.authority_index,
            };

            // Safely retrieve the validator by the authority index
            return validators.get(authority_index as usize).cloned();
        } else if is_aura(*engine) {
            // Aura uses the slot number modulo the validator count
            let slot_number = u64::from_le_bytes(data[..8].try_into().ok()?);
            let index = (slot_number as usize) % validators.len();
            return validators.get(index).cloned();
        }
    }

    // Process Consensus logs for PoW
    if let Some(DigestItem::Consensus(engine, data)) = digest_logs
        .iter()
        .find(|item| matches!(item, DigestItem::Consensus(..)))
    {
        if is_pow(*engine) {
            // PoW includes the author directly in the data
            let account_id: [u8; 32] = data.clone().try_into().ok()?;
            return Some(AccountId32::from(account_id));
        }
    }

    None
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

        // Extract arguments
        let args = serialize_args(extrinsic.field_values().ok());

        // Fetch events asynchronously
        let events = extrinsic.events().await.unwrap();

        // Extract field values from events
        let event_info = events
            .iter()
            .filter_map(|event| match event {
                Ok(e) => e.field_values().ok(),
                Err(err) => {
                    tracing::error!("Error processing event: {:?}", err);
                    None
                }
            })
            .collect();

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
            events: event_info,
        });
    }

    result
}

fn serialize_args(args: Option<Composite<u32>>) -> Option<serde_json::Value> {
    args.map(|composite| match composite {
        Composite::Named(named_fields) => {
            let obj: serde_json::Map<String, serde_json::Value> = named_fields
                .into_iter()
                .map(|(key, value)| (key, serialize_value(value)))
                .collect();
            serde_json::Value::Object(obj)
        }
        Composite::Unnamed(unnamed_fields) => {
            let array: Vec<serde_json::Value> =
                unnamed_fields.into_iter().map(serialize_value).collect();
            serde_json::Value::Array(array)
        }
    })
}

fn serialize_value(value: Value<u32>) -> serde_json::Value {
    match value.value {
        ValueDef::Primitive(primitive) => match primitive {
            Primitive::Bool(b) => serde_json::Value::Bool(b),
            Primitive::Char(c) => serde_json::Value::String(c.to_string()),
            Primitive::String(s) => serde_json::Value::String(s),
            Primitive::U128(num) => serde_json::Value::String(num.to_string()),
            Primitive::I128(num) => serde_json::Value::String(num.to_string()),
            Primitive::U256(bytes) | Primitive::I256(bytes) => {
                serde_json::Value::String(format!("0x{}", hex::encode(bytes)))
            }
        },
        ValueDef::Composite(composite) => serialize_composite(composite),
        ValueDef::Variant(variant) => {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "variant".to_string(),
                serde_json::Value::String(variant.name),
            );
            obj.insert(
                "fields".to_string(),
                serde_json::Value::Array(
                    variant.values.into_values().map(serialize_value).collect(),
                ),
            );
            serde_json::Value::Object(obj)
        }
        ValueDef::BitSequence(bits) => serde_json::Value::String(format!("{:?}", bits)),
    }
}

fn serialize_composite(composite: Composite<u32>) -> serde_json::Value {
    match composite {
        Composite::Named(named_fields) => {
            let obj: serde_json::Map<String, serde_json::Value> = named_fields
                .into_iter()
                .map(|(key, value)| (key, serialize_value(value)))
                .collect();
            serde_json::Value::Object(obj)
        }
        Composite::Unnamed(unnamed_fields) => {
            // Check if this is a byte array
            if unnamed_fields
                .iter()
                .all(|v| matches!(v.value, ValueDef::Primitive(Primitive::U128(_))))
            {
                // Convert unnamed fields into a hex string
                let bytes: Vec<u8> = unnamed_fields
                    .into_iter()
                    .filter_map(|v| match v.value {
                        ValueDef::Primitive(Primitive::U128(num)) if num <= 255 => Some(num as u8),
                        _ => None,
                    })
                    .collect();
                serde_json::Value::String(format!("0x{}", hex::encode(bytes)))
            } else {
                let array: Vec<serde_json::Value> =
                    unnamed_fields.into_iter().map(serialize_value).collect();
                serde_json::Value::Array(array)
            }
        }
    }
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
        let validators = vec![
            AccountId32::from([0; 32]),
            AccountId32::from([1; 32]),
            AccountId32::from([2; 32]),
        ];

        let author = extract_author(&logs, validators);

        assert_eq!(
            author,
            Some(AccountId32::from([1; 32])),
            "The author ID should be the validator corresponding to slot 1."
        );
    }

    #[test]
    fn test_extract_author_babe() {
        let logs = vec![DigestItem::PreRuntime(*b"BABE", vec![2, 0, 0, 0])]; // Slot index = 2
        let validators = vec![
            AccountId32::from([0; 32]),
            AccountId32::from([1; 32]),
            AccountId32::from([2; 32]),
        ];

        let author = extract_author(&logs, validators);

        assert_eq!(
            author,
            Some(AccountId32::from([2; 32])),
            "The author ID should be the validator at index 2."
        );
    }

    #[test]
    fn test_extract_author_nimbus() {
        let logs = vec![DigestItem::Seal(*b"nmbs", [1; 32].to_vec())]; // Author ID directly in data
        let validators = vec![
            AccountId32::from([0; 32]),
            AccountId32::from([1; 32]),
            AccountId32::from([2; 32]),
        ];

        let author = extract_author(&logs, validators);

        assert_eq!(
            author,
            Some(AccountId32::from([1; 32])),
            "The author ID should be extracted directly from the Seal digest."
        );
    }

    #[test]
    fn test_extract_author_no_validators() {
        let logs = vec![DigestItem::PreRuntime(*b"aura", vec![0; 8])]; // Slot number = 0
        let validators: Vec<AccountId32> = None; // No validators provided

        let author = extract_author(&logs, validators);

        assert_eq!(author, None, "No validators should result in no author ID.");
    }

    #[test]
    fn test_extract_author_no_logs() {
        let logs: Vec<DigestItem> = vec![]; // No logs
        let validators = vec![
            AccountId32::from([0; 32]),
            AccountId32::from([1; 32]),
            AccountId32::from([2; 32]),
        ];

        let author = extract_author(&logs, validators);

        assert_eq!(author, None, "No logs should result in no author ID.");
    }

    #[test]
    fn test_extract_author_invalid_slot_index() {
        let logs = vec![DigestItem::PreRuntime(*b"BABE", vec![255, 255, 255, 255])]; // Invalid slot index
        let validators = vec![
            AccountId32::from([0; 32]),
            AccountId32::from([1; 32]),
            AccountId32::from([2; 32]),
        ];

        let author = extract_author(&logs, validators);

        assert_eq!(
            author, None,
            "An invalid slot index should result in no author ID."
        );
    }
}
