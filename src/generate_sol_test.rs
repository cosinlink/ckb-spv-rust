use crate::proof_generator::get_tx_index;
use crate::types::{JsonMerkleProof, MergeByte32, TransactionProof, MAINNET_RPC_URL};
use ckb_jsonrpc_types::Uint32;
use ckb_jsonrpc_types::{JsonBytes, ScriptHashType};
use ckb_sdk::rpc::{CellInput, OutPoint};
use ckb_sdk::{
    rpc::{BlockView, RawHttpRpcClient, Script, TransactionView, TransactionWithStatus},
    wallet::KeyStore,
    GenesisInfo, HttpRpcClient,
};
use ckb_types::{
    bytes::Bytes,
    core::{self, cell::CellProvider, TransactionBuilder},
    h256,
    packed::{self, Block, Byte32, Header, ProposalShortId},
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
    input: Vec<I>,
    output: Vec<O>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcData {
    extract_since: TestCase<String, String>,
    extract_previous_output: TestCase<String, String>,

    extract_code_hash: TestCase<String, H256>,
    extract_hash_type: TestCase<String, u8>,
    extract_args: TestCase<String, JsonBytes>,
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
        base_path.push("..");
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
}

#[test]
fn test_loader() {
    let tx_hashes = vec![
        h256!("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"),
        h256!("0xa05f28c9b867f8c5682039c10d8e864cf661685252aa74a008d255c33813bb81"),
        h256!("0xb269a43a5f5c028fea8fccceecda96281836a472f6f94ad7a70c22c7470da59a"),
        h256!("0x7356169e91f6c0eb7ba74a34232e49f16f011b3e97ede76f0c66cf230139a8ea"),
    ];
    generate_script_tests(tx_hashes);
}

pub fn generate_script_tests(tx_hashes: Vec<H256>) {
    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
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

    to_json_test(scripts, &mut cell_inputs);
}

fn to_json_test(scripts: Vec<Script>, cell_inputs: &mut Vec<CellInput>) {
    // CellInput items test
    let mut inputs = vec![];
    let mut since_vec = vec![];
    let mut previous_outputs = vec![];

    for cell_input in cell_inputs {
        since_vec.push(format!("{}", cell_input.since.0));

        let outpoint: packed::OutPoint = cell_input.previous_output.clone().into();
        previous_outputs.push(format!("0x{}", hex::encode(outpoint.as_bytes().as_ref())));

        let input: packed::CellInput = cell_input.clone().into();
        inputs.push(format!("0x{}", hex::encode(input.as_bytes().as_ref())));
    }

    // Script items test
    let mut script_inputs = vec![];
    let mut code_hashes = vec![];
    let mut hash_types = vec![];
    let mut args_vec = vec![];
    for script in scripts {
        code_hashes.push(script.code_hash.clone());
        hash_types.push(script.hash_type.clone() as u8);
        args_vec.push(script.args.clone());
        let mol_script: packed::Script = script.into();
        script_inputs.push(format!("0x{}", hex::encode(mol_script.as_bytes().as_ref())));
    }

    let rpc_data = RpcData {
        extract_since: TestCase {
            input: inputs.clone(),
            output: since_vec.clone(),
        },

        extract_previous_output: TestCase {
            input: inputs.clone(),
            output: previous_outputs.clone(),
        },

        extract_code_hash: TestCase {
            input: script_inputs.clone(),
            output: code_hashes.clone(),
        },

        extract_hash_type: TestCase {
            input: script_inputs.clone(),
            output: hash_types.clone(),
        },
        extract_args: TestCase {
            input: script_inputs.clone(),
            output: args_vec.clone(),
        },
    };

    let str = serde_json::to_string(&rpc_data).unwrap();
    let dir = env::current_dir().unwrap();
    let mut base_path = PathBuf::new();
    base_path.push(dir);
    base_path.push("rpc-data");
    base_path.push(TEST_FILE_NAME);
    dbg!(base_path.clone());
    dbg!(fs::write(base_path, str.as_str()));
}
