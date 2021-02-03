use crate::proof_generator::get_tx_index;
use crate::proof_generator::{generate_ckb_history_tx_root_proof, generate_ckb_single_tx_proof};
use crate::proof_verifier::{verify_ckb_history_tx_root_proof, verify_ckb_single_tx_proof};
use crate::types::generated::ckb_tx_proof;
use crate::types::transaction_proof::{
    CKBHistoryTxRootProof, CkbTxProof, JsonMerkleProof, MergeByte32, MAINNET_RPC_URL,
};
use ckb_jsonrpc_types::Uint32;
use ckb_jsonrpc_types::{JsonBytes, ScriptHashType};
use ckb_pow::pow_message;
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
    core::{self, cell::CellProvider, EpochNumberWithFraction, TransactionBuilder},
    h256,
    packed::{self, Block, ProposalShortId},
    prelude::*,
    utilities::{merkle_root, CBMT},
    H256,
};
use eaglesong::eaglesong;

use faster_hex::{hex_decode, hex_encode};
use merkle_cbt::{merkle_tree::Merge, MerkleProof as ExMerkleProof, MerkleProof, CBMT as ExCBMT};
use rand::{thread_rng, Rng, SeedableRng};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json;
use std::convert::{TryFrom, TryInto};
use std::{collections::HashSet, env, fmt, fs, marker::PhantomData, path::PathBuf};
use std::{thread, time};

const RPC_DATA_NAME: &str = "origin_data.json";
const TEST_VIEWCKB_FILE_NAME: &str = "testVectors.json";
const TEST_VIEWSPV_FILE_NAME: &str = "testSPV.json";
const TEST_VIEW_HISTORY_TX_ROOT_FILE_NAME: &str = "testHistoryTxRoot.json";
const TEST_HEADERS_BENCH_FILE_NAME: &str = "testHeadersBench.json";
const TEST_FUZZY_TEST_FILE_NAME: &str = "testEaglesongFuzzy.json";
const TEST_DATA_DIR: &str = "test-data";

pub const NUMBER_OFFSET: usize = 0;
pub const NUMBER_BITS: usize = 24;
pub const NUMBER_MAXIMUM_VALUE: u64 = (1u64 << NUMBER_BITS as u64);
pub const NUMBER_MASK: u64 = (NUMBER_MAXIMUM_VALUE - 1);

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
pub struct CKBRpcData {
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
    calculate_block_hash: Vec<TestCase<String, H256>>,
    calculate_eaglesong: Vec<TestCase<String, H256>>,

    // headers
    index_header_vec: Vec<TestCase<String, Vec<String>>>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct SpvRpcData {
    // members of CKBTxProof
    extract_tx_merkle_index: Vec<TestCase<String, String>>,
    extract_block_number: Vec<TestCase<String, String>>,
    extract_block_hash: Vec<TestCase<String, H256>>,
    extract_tx_hash: Vec<TestCase<String, H256>>,
    extract_witnesses_root: Vec<TestCase<String, H256>>,
    extract_lemmas: Vec<TestCase<String, String>>,
    expected_transactions_root: Vec<TestCase<String, H256>>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct HistoryTxRootProofData {
    // members of HistoryTxRootProof
    extract_init_block_number: Vec<TestCase<String, String>>,
    extract_latest_block_number: Vec<TestCase<String, String>>,
    extract_indices: Vec<TestCase<String, String>>,
    extract_proof_leaves: Vec<TestCase<String, String>>,
    extract_lemmas: Vec<TestCase<String, String>>,
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
        base_path.push(TEST_DATA_DIR);
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

    pub fn store_test_data<T: Serialize>(&self, filename: &str, test_data: &T) {
        let mut path = self.0.clone();
        path.push(filename);
        let str = serde_json::to_string(test_data).unwrap();
        fs::write(path, str.as_str());
    }
}

#[test]
fn generate_view_ckb_test() {
    dbg!(NUMBER_MASK);
    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
    let tx_hashes = vec![
        h256!("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"),
        h256!("0xa05f28c9b867f8c5682039c10d8e864cf661685252aa74a008d255c33813bb81"),
        h256!("0xb269a43a5f5c028fea8fccceecda96281836a472f6f94ad7a70c22c7470da59a"),
        h256!("0x7356169e91f6c0eb7ba74a34232e49f16f011b3e97ede76f0c66cf230139a8ea"),
    ];

    let block_numbers = vec![2000, 2001, 2002, 2003, 2004, 2005, 2006];
    let mut test_data = CKBRpcData::default();
    generate_script_tests(&mut rpc_client, &mut test_data, tx_hashes);
    generate_header_tests(&mut rpc_client, &mut test_data, block_numbers);

    // store json string to file
    Loader::default().store_test_data(TEST_VIEWCKB_FILE_NAME, &test_data);
}

#[test]
fn generate_view_spv_test() {
    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
    let tx_hashes = vec![
        h256!("0x39e33c8ad2e7e4eb71610d2bcdfbb0cb0fde2f96418256914ad2f5be1d6e9331"),
        h256!("0x3827275f7a9785b09d85c2e687338a3dfb3978656747c2449685f31293210e2f"),
        h256!("0x02acc5ccc6073f371df6a89a6a1c22b567dbd1d82be2114c277d3f0f0cd07915"),
        h256!("0x5094be43fd4c45fdf9446d1f46d9ce0124af6d2b9cdaed21ff5840ad684f8a02"),
        h256!("0x0b332365bbdf1e7392af801e3f74496dfe94c22ac41e0e4b3924f352da5a3795"),
        h256!("0x55fbffa77f25fc53425f85d2fd7999b18a10bb55b3d70e9e61037a1138955c88"),
        h256!("0xce08d2fd4fe275ceddff74c8ae5d6ac27807b5c7788ed951c4f8e1ac507119a1"),
        h256!("0x477f3cce8c1a61d35056dec9e0e2ba135614ce93cca3f898fe702b9774ee4d76"),
    ];

    let mut test_data = SpvRpcData::default();
    generate_spv_tests(&mut test_data, tx_hashes);

    // store json string to file
    Loader::default().store_test_data(TEST_VIEWSPV_FILE_NAME, &test_data);
}

#[test]
fn generate_view_history_tx_proof_test() {
    let mut test_data = HistoryTxRootProofData::default();
    generate_tx_root_proof_test(&mut test_data);

    // store json string to file
    Loader::default().store_test_data(TEST_VIEW_HISTORY_TX_ROOT_FILE_NAME, &test_data);
}

#[test]
fn generate_headers_benchmark_test() {
    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
    let mut test_data = CKBRpcData::default();

    let mut block_numbers = vec![];
    for i in 3000..3200 {
        block_numbers.push(i)
    }
    generate_header_tests(&mut rpc_client, &mut test_data, block_numbers);

    // store json string to file
    Loader::default().store_test_data(TEST_HEADERS_BENCH_FILE_NAME, &test_data);
}

#[test]
fn generate_eaglesong_fuzzy_test() {
    let mut test_data = CKBRpcData::default();
    let test_times = 1000;

    generate_fuzzy_tests(&mut test_data, test_times);

    // store json string to file
    Loader::default().store_test_data(TEST_FUZZY_TEST_FILE_NAME, &test_data);
}

pub fn generate_script_tests(
    rpc_client: &mut HttpRpcClient,
    test_data: &mut CKBRpcData,
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

pub fn generate_spv_tests(test_data: &mut SpvRpcData, tx_hashes: Vec<H256>) {
    let mut hs_tx_proofs = HashSet::new();
    for tx_hash in tx_hashes {
        let tx_proof =
            generate_ckb_single_tx_proof(tx_hash.clone()).expect("CKBTxProof generated failed");
        hs_tx_proofs.insert(tx_proof);
    }
    let mut tx_proofs: Vec<CkbTxProof> = hs_tx_proofs.into_iter().collect();

    // tx_proof items test
    for tx_proof in tx_proofs {
        let tx_proof_clone = tx_proof.clone();
        let mol_tx_proof: ckb_tx_proof::CkbTxProof = tx_proof.clone().into();
        let mol_hex = format!("0x{}", hex::encode(mol_tx_proof.as_bytes().as_ref()));

        test_data.extract_tx_merkle_index.push(TestCase {
            input: mol_hex.clone(),
            output: format!("{}", tx_proof.tx_merkle_index),
        });

        test_data.extract_block_number.push(TestCase {
            input: mol_hex.clone(),
            output: format!("{}", tx_proof.block_number),
        });

        test_data.extract_block_hash.push(TestCase {
            input: mol_hex.clone(),
            output: tx_proof.block_hash,
        });

        test_data.extract_tx_hash.push(TestCase {
            input: mol_hex.clone(),
            output: tx_proof.tx_hash,
        });

        test_data.extract_witnesses_root.push(TestCase {
            input: mol_hex.clone(),
            output: tx_proof.witnesses_root,
        });

        test_data.extract_lemmas.push(TestCase {
            input: mol_hex.clone(),
            output: format!(
                "0x{}",
                hex::encode(mol_tx_proof.lemmas().as_bytes().slice(4..))
            ),
        });

        test_data.expected_transactions_root.push(TestCase {
            input: mol_hex.clone(),
            output: verify_ckb_single_tx_proof(tx_proof_clone).unwrap(),
        })
    }
}

pub fn generate_tx_root_proof_test(test_data: &mut HistoryTxRootProofData) {
    let block_numbers_vec = vec![
        vec![1u64, 2, 3, 4, 5, 6, 7, 8, 12, 16],
        vec![1u64, 4, 5, 6, 7, 8, 12, 16],
        vec![1u64, 9, 13, 16],
        vec![3100u64, 3196, 3300],
        vec![3100u64, 3196, 3199, 3222, 3233, 3300],
        // vec![93100u64, 93196, 97700],
    ];

    let mut history_tx_root_proofs: Vec<CKBHistoryTxRootProof> = vec![];
    for numbers in block_numbers_vec {
        dbg!(numbers.clone());
        let history_tx_root_proof = generate_ckb_history_tx_root_proof(
            numbers.first().unwrap().clone(),
            numbers.last().unwrap().clone(),
            numbers,
        )
        .expect("CKBTxProof generated failed");
        history_tx_root_proofs.push(history_tx_root_proof);
        dbg!("generate history_tx_root_proof success");
    }

    // tx_proof items test
    for proof in history_tx_root_proofs {
        let expect_root = verify_ckb_history_tx_root_proof(proof.clone()).unwrap();
        dbg!(expect_root.pack());
        let mol_proof: ckb_tx_proof::CkbHistoryTxRootProof = proof.clone().into();
        let mol_hex = format!("0x{}", hex::encode(mol_proof.as_bytes().as_ref()));

        test_data.extract_init_block_number.push(TestCase {
            input: mol_hex.clone(),
            output: format!("{}", proof.init_block_number),
        });

        test_data.extract_latest_block_number.push(TestCase {
            input: mol_hex.clone(),
            output: format!("{}", proof.latest_block_number),
        });

        test_data.extract_indices.push(TestCase {
            input: mol_hex.clone(),
            output: format!(
                "0x{}",
                hex::encode(mol_proof.indices().as_bytes().slice(4..))
            ),
        });

        test_data.extract_proof_leaves.push(TestCase {
            input: mol_hex.clone(),
            output: format!(
                "0x{}",
                hex::encode(mol_proof.proof_leaves().as_bytes().slice(4..))
            ),
        });

        test_data.extract_lemmas.push(TestCase {
            input: mol_hex.clone(),
            output: format!(
                "0x{}",
                hex::encode(mol_proof.lemmas().as_bytes().slice(4..))
            ),
        });
    }
}

pub fn generate_header_tests(
    rpc_client: &mut HttpRpcClient,
    test_data: &mut CKBRpcData,
    block_numbers: Vec<u64>,
) {
    // let mut hs_headers = HashSet::new();
    // let mut hs_block_hash = HashSet::new();
    let mut headers: Vec<Header> = vec![];
    let mut block_hashes: Vec<H256> = vec![];

    for number in block_numbers {
        match rpc_client.get_block_by_number(number).unwrap() {
            Some(block) => {
                headers.push(block.header.inner);
                block_hashes.push(block.header.hash);
            }
            None => continue,
        }

        let ten_millis = time::Duration::from_secs(2);
        thread::sleep(ten_millis);
    }

    // generate headers vector
    let all_header_vec = headers
        .iter()
        .map(|header| header.clone().into())
        .collect::<Vec<packed::Header>>();

    let mut all_headers_output = vec![];
    let mut all_headers_input = vec![];

    for (index, header) in headers.iter().enumerate() {
        // all_headers[index..end] is test-data origin data
        let header_vec = all_header_vec[index..].to_vec();
        let mol_header_vec = packed::HeaderVec::new_builder().set(header_vec).build();
        all_headers_input.push(format!("0x{}", hex::encode(mol_header_vec.as_bytes())));

        let mol_header: packed::Header = header.clone().into();
        all_headers_output.push(format!("0x{}", hex::encode(mol_header.clone().as_bytes())));
    }

    for (index, header) in headers.iter().enumerate() {
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
            input: mol_header_hex.clone(),
            output: format!("{}", nonce),
        });

        let version: u32 = mol_raw_header.version().unpack();
        let compact_target: u32 = mol_raw_header.compact_target().unpack();
        let timestamp: u64 = mol_raw_header.timestamp().unpack();
        let number: u64 = mol_raw_header.number().unpack();
        let epoch_number: u64 = {
            let value = header.epoch;
            let epoch = core::EpochNumberWithFraction::from_full_value(value.0);
            epoch.number()
        };

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
            output: format!("{}", epoch_number),
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
        test_data.calculate_block_hash.push(TestCase {
            input: mol_header_hex.clone(),
            output: block_hashes[index].clone(),
        });

        let (input, eaglesong_hash) = {
            let input = pow_message(&mol_header.as_reader().calc_pow_hash(), nonce);
            let mut output = [0u8; 32];
            eaglesong(&input, &mut output);
            (input, H256(output))
        };

        test_data.calculate_eaglesong.push(TestCase {
            input: format!("0x{}", hex::encode(&input[..])),
            output: eaglesong_hash,
        });

        // headerVec from index to end
        let expect_header_vec = all_headers_output[index..].to_vec();
        test_data.index_header_vec.push(TestCase {
            input: all_headers_input[index].clone(),
            output: expect_header_vec,
        });
    }
}

pub fn generate_fuzzy_tests(test_data: &mut CKBRpcData, test_times: u32) {
    for _ in 0..test_times {
        let mut rng = thread_rng();
        let (input, eaglesong_hash) = {
            let mut input_32 = [0u8; 32];
            rng.fill(&mut input_32);

            let mut input_16 = [0u8; 16];
            rng.fill(&mut input_16);

            let input_48: Vec<u8> = [&input_32[..], &input_16[..]].concat();

            let mut output = [0u8; 32];
            eaglesong(input_48.as_slice(), &mut output);
            (input_48, H256(output))
        };

        test_data.calculate_eaglesong.push(TestCase {
            input: format!(
                "0x{}00000000000000000000000000000000",
                hex::encode(&input[..])
            ),
            output: eaglesong_hash,
        });
    }
}
