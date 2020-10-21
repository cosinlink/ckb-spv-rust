use crate::proof_generator::get_tx_index;
use crate::types::transaction_proof::{JsonMerkleProof, MergeByte32, TransactionProof, MAINNET_RPC_URL};
use ckb_jsonrpc_types::Uint32;
use ckb_jsonrpc_types::{JsonBytes, ScriptHashType};
use ckb_sdk::rpc::{CellInput, OutPoint};
use ckb_sdk::{
    rpc::{
        BlockView, Byte32, Header, RawHttpRpcClient, Script, TransactionView, TransactionWithStatus,
    },
    wallet::KeyStore,
    GenesisInfo, HttpRpcClient,
};
use ckb_types::{
    bytes::Bytes,
    core::{self, cell::CellProvider, TransactionBuilder},
    h256,
    packed::{self, Block, ProposalShortId},
    prelude::*,
    utilities::{merkle_root, CBMT},
    H256,
};
use faster_hex::hex_decode;
use merkle_cbt::{merkle_tree::Merge, MerkleProof as ExMerkleProof, MerkleProof, CBMT as ExCBMT};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json;
use std::convert::{TryFrom, TryInto};
use std::{collections::HashSet, env, fmt, fs, marker::PhantomData, path::PathBuf};

const RPC_DATA_NAME: &str = "origin_data.json";
const TEST_FILE_NAME: &str = "testVectors.json";

pub struct Loader(PathBuf);

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConfigScript {
    pub code_hash: String,
    pub hash_type: String,
    pub args: String,
}

impl TryFrom<ConfigScript> for Script {
    type Error = hex::FromHexError;

    fn try_from(script: ConfigScript) -> Result<Self, Self::Error> {
        let bytes = hex::decode(&script.code_hash.as_bytes()[2..])?;
        let code_hash = H256::from_slice(bytes.as_slice()).expect("code_hash invalid");

        let bytes = hex::decode(&script.args.as_bytes()[2..])?;
        let args = JsonBytes::from_vec(bytes);

        let hash_type = match script.hash_type.as_str() {
            "data" => ScriptHashType::Data,
            "type" => ScriptHashType::Type,
            _ => panic!("hash_type invalid"),
        };

        Ok(Self {
            code_hash,
            hash_type,
            args,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TestCase<I, O> {
    input: I,
    output: O,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct RpcData {
    // members of CellInput
    extract_since: Vec<TestCase<String, String>>,
    extract_previous_output: Vec<TestCase<String, String>>,

    // members of Script
    extract_code_hash: Vec<TestCase<String, H256>>,
    extract_hash_type: Vec<TestCase<String, u8>>,
    extract_args: Vec<TestCase<String, String>>,

    // members of Header
    extract_raw_header: Vec<TestCase<String, String>>,
    extract_nonce: Vec<TestCase<String, String>>,

    // members of RawHeader
    extract_version: Vec<TestCase<String, String>>,
    extract_compact_target: Vec<TestCase<String, String>>,
    extract_timestamp: Vec<TestCase<String, String>>,
    extract_block_number: Vec<TestCase<String, String>>,
    extract_epoch: Vec<TestCase<String, String>>,
    extract_parent_hash: Vec<TestCase<String, H256>>,
    extract_transactions_root: Vec<TestCase<String, H256>>,
    extract_uncles_hash: Vec<TestCase<String, H256>>,
    extract_dao: Vec<TestCase<String, Byte32>>,
}

impl Default for Loader {
    fn default() -> Self {
        Self::with_current_dir()
    }
}

impl Loader {
    fn with_current_dir() -> Self {
        let dir = env::current_dir().unwrap();
        let mut base_path = PathBuf::new();
        base_path.push(dir);
        base_path.push("rpc-data");
        Loader(base_path)
    }

    pub fn load_binary(&self, name: &str) -> Bytes {
        let mut path = self.0.clone();
        path.push(name);
        fs::read(path).expect("binary").into()
    }

    pub fn load_rpc_data(&self, name: &str) -> serde_json::Value {
        let mut config_path = self.0.clone();
        config_path.push(name);
        let json_str = fs::read_to_string(&config_path).expect("rpc data load failed");
        serde_json::from_str(&json_str).expect("invalid rpc data json")
    }

    pub fn store_test_data(&self, filename: &str, test_data: &RpcData) {
        let mut path = self.0.clone();
        path.push(filename);
        let str = serde_json::to_string(test_data).unwrap();
        fs::write(path, str.as_str());
    }
}

#[test]
fn test_loader() {
    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
    let tx_hashes = vec![
        h256!("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"),
        h256!("0xa05f28c9b867f8c5682039c10d8e864cf661685252aa74a008d255c33813bb81"),
        h256!("0xb269a43a5f5c028fea8fccceecda96281836a472f6f94ad7a70c22c7470da59a"),
        h256!("0x7356169e91f6c0eb7ba74a34232e49f16f011b3e97ede76f0c66cf230139a8ea"),
    ];

    let block_numbers = vec![1, 2, 5, 2000, 2_985_150];
    let mut test_data = RpcData::default();
    generate_script_tests(&mut rpc_client, &mut test_data, tx_hashes);
    generate_header_tests(&mut rpc_client, &mut test_data, block_numbers);

    // store json string to file
    Loader::default().store_test_data(TEST_FILE_NAME, &test_data);
}

pub fn generate_script_tests(
    rpc_client: &mut HttpRpcClient,
    test_data: &mut RpcData,
    tx_hashes: Vec<H256>,
) {
    let mut hs_outputs = HashSet::new();
    let mut hs_inputs = HashSet::new();
    for tx_hash in tx_hashes {
        match rpc_client.get_transaction(tx_hash.clone()).unwrap() {
            Some(tx_with_status) => {
                for output in tx_with_status.transaction.inner.outputs {
                    hs_outputs.insert(output.lock);
                    if output.type_.is_some() {
                        hs_outputs.insert(output.type_.unwrap());
                    }
                }

                for input in tx_with_status.transaction.inner.inputs {
                    hs_inputs.insert(input);
                }
            }
            None => continue,
        }
    }
    let mut scripts: Vec<Script> = hs_outputs.into_iter().collect();
    let mut cell_inputs: Vec<CellInput> = hs_inputs.into_iter().collect();

    // add more since and outpoint tests
    // since
    pub const LOCK_TYPE_FLAG: u64 = 1 << 63;
    pub const SINCE_TYPE_TIMESTAMP: u64 = 0x4000_0000_0000_0000;
    // 24 * 3600 means 1 day, the unit is second
    pub const SINCE_SIGNER_TIMEOUT: u64 = LOCK_TYPE_FLAG | SINCE_TYPE_TIMESTAMP | 24 * 3600;
    let tx_hash = h256!("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c");
    let out_point = OutPoint { tx_hash, index: 0 };

    cell_inputs.push(CellInput {
        previous_output: out_point,
        since: SINCE_SIGNER_TIMEOUT.into(),
    });

    // CellInput items test
    for cell_input in cell_inputs {
        let mol_input: packed::CellInput = cell_input.clone().into();
        let mol_hex = format!("0x{}", hex::encode(mol_input.as_bytes().as_ref()));
        test_data.extract_since.push(TestCase {
            input: mol_hex.clone(),
            output: format!("{}", cell_input.since.0),
        });

        let outpoint: packed::OutPoint = cell_input.previous_output.clone().into();
        test_data.extract_previous_output.push(TestCase {
            input: mol_hex,
            output: format!("0x{}", hex::encode(outpoint.as_bytes().as_ref())),
        });
    }

    // Script items test
    for script in scripts {
        let mol_script: packed::Script = script.clone().into();
        let mol_hex = format!("0x{}", hex::encode(mol_script.as_bytes().as_ref()));

        test_data.extract_code_hash.push(TestCase {
            input: mol_hex.clone(),
            output: script.code_hash.clone(),
        });

        test_data.extract_hash_type.push(TestCase {
            input: mol_hex.clone(),
            output: script.hash_type.clone() as u8,
        });

        test_data.extract_args.push(TestCase {
            input: mol_hex.clone(),
            output: format!("0x{}", hex::encode(script.args.as_bytes())),
        });
    }
}

pub fn generate_header_tests(
    rpc_client: &mut HttpRpcClient,
    test_data: &mut RpcData,
    block_numbers: Vec<u64>,
) {
    let mut hs_headers = HashSet::new();
    for number in block_numbers {
        match rpc_client.get_block_by_number(number).unwrap() {
            Some(block) => {
                hs_headers.insert(block.header.inner);
            }
            None => continue,
        }
    }
    let mut headers: Vec<Header> = hs_headers.into_iter().collect();

    for header in headers {
        let mol_header: packed::Header = header.clone().into();
        let mol_raw_header = mol_header.raw();

        let mol_header_hex = format!("0x{}", hex::encode(mol_header.as_bytes().as_ref()));
        let mol_raw_header_hex = format!("0x{}", hex::encode(mol_raw_header.as_bytes().as_ref()));

        test_data.extract_raw_header.push(TestCase {
            input: mol_header_hex.clone(),
            output: mol_raw_header_hex.clone(),
        });

        let nonce: u128 = header.nonce.into();
        test_data.extract_nonce.push(TestCase {
            input: mol_header_hex,
            output: format!("{}", nonce),
        });

        let version: u32 = mol_raw_header.version().unpack();
        let compact_target: u32 = mol_raw_header.compact_target().unpack();
        let timestamp: u64 = mol_raw_header.timestamp().unpack();
        let number: u64 = mol_raw_header.number().unpack();
        let epoch: u64 = mol_raw_header.epoch().unpack();

        test_data.extract_version.push(TestCase {
            input: mol_raw_header_hex.clone(),
            output: format!("{}", version),
        });
        test_data.extract_compact_target.push(TestCase {
            input: mol_raw_header_hex.clone(),
            output: format!("{}", compact_target),
        });
        test_data.extract_timestamp.push(TestCase {
            input: mol_raw_header_hex.clone(),
            output: format!("{}", timestamp),
        });
        test_data.extract_block_number.push(TestCase {
            input: mol_raw_header_hex.clone(),
            output: format!("{}", number),
        });
        test_data.extract_epoch.push(TestCase {
            input: mol_raw_header_hex.clone(),
            output: format!("{}", epoch),
        });

        test_data.extract_parent_hash.push(TestCase {
            input: mol_raw_header_hex.clone(),
            output: header.parent_hash.clone(),
        });
        test_data.extract_transactions_root.push(TestCase {
            input: mol_raw_header_hex.clone(),
            output: header.transactions_root.clone(),
        });
        test_data.extract_uncles_hash.push(TestCase {
            input: mol_raw_header_hex.clone(),
            output: header.uncles_hash.clone(),
        });
        test_data.extract_dao.push(TestCase {
            input: mol_raw_header_hex.clone(),
            output: header.dao.clone(),
        });
    }
}
