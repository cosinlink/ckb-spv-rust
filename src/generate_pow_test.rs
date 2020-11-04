use crate::proof_generator::generate_ckb_single_tx_proof;
use crate::proof_generator::get_tx_index;
use crate::proof_verifier::verify_ckb_single_tx_proof;
use crate::types::generated::ckb_tx_proof;
use crate::types::transaction_proof::{CkbTxProof, JsonMerkleProof, MergeByte32, MAINNET_RPC_URL};
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
    core::{BlockNumber, HeaderView},
    h256,
    packed::{self, Block, ProposalShortId},
    prelude::*,
    utilities::{
        compact_to_difficulty, compact_to_target, difficulty_to_compact, merkle_root, CBMT,
    },
    H256,
};
use numext_fixed_uint::prelude::UintConvert;
use numext_fixed_uint::{u256, u512, U256, U512};

use ckb_pow::pow_message;

use eaglesong::eaglesong;
use faster_hex::{hex_decode, hex_encode};
use merkle_cbt::{merkle_tree::Merge, MerkleProof as ExMerkleProof, MerkleProof, CBMT as ExCBMT};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json;
use std::convert::{TryFrom, TryInto};
use std::{collections::HashSet, env, fmt, fs, marker::PhantomData, path::PathBuf};
const RPC_DATA_NAME: &str = "origin_data.json";
const TEST_VIEWCKB_FILE_NAME: &str = "testVectors.json";
const TEST_VIEWSPV_FILE_NAME: &str = "testSPV.json";
const TEST_DATA_DIR: &str = "test-data";

#[test]
pub fn test_pow() {
    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
    let tx_hashes = vec![
        h256!("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"),
        h256!("0xa05f28c9b867f8c5682039c10d8e864cf661685252aa74a008d255c33813bb81"),
        h256!("0xb269a43a5f5c028fea8fccceecda96281836a472f6f94ad7a70c22c7470da59a"),
        h256!("0x7356169e91f6c0eb7ba74a34232e49f16f011b3e97ede76f0c66cf230139a8ea"),
    ];

    let header = match rpc_client.get_block_by_number(1111).unwrap() {
        Some(block) => block.header.inner,
        None => return,
    };
    let mol_header: packed::Header = header.clone().into();
    let mol_raw_header = mol_header.raw();
    dbg!(format!("0x{}", hex::encode(mol_header.clone().as_bytes())));

    let pow_msg = pow_message(
        &mol_header.as_reader().calc_pow_hash(),
        mol_header.nonce().unpack(),
    );
    dbg!(format!("0x{}", hex::encode(pow_msg.as_ref())));

    let mut output = [0u8; 32];
    eaglesong(&pow_msg, &mut output);
    dbg!(format!("0x{}", hex::encode(output.as_ref())));

    let compact = mol_raw_header.compact_target().unpack();
    let (block_target, overflow) = compact_to_target(compact);
    dbg!(format!("target: {}, overflow: {}", block_target, overflow));

    dbg!(format!(
        "block eag hash: {}",
        U256::from_big_endian(&output[..]).unwrap()
    ));

    let difficulty = compact_to_difficulty(compact);
    dbg!(format!("block difficulty: {}", difficulty));
}

fn target_to_difficulty(target: &U256) -> U256 {
    const ONE: U256 = U256::one();
    // ONE << 256
    const HSPACE: U512 =
        u512!("0x10000000000000000000000000000000000000000000000000000000000000000");

    if target == &ONE {
        U256::max_value()
    } else {
        let (target, _): (U512, bool) = target.convert_into();
        (HSPACE / target).convert_into().0
    }
}

fn my_func_todifficulty(target: &U256) -> U256 {
    const ONE: U256 = U256::one();
    // ONE << 256
    const HSPACE: U512 =
        u512!("0x10000000000000000000000000000000000000000000000000000000000000000");

    if target == &ONE {
        return U256::max_value();
    }

    let left: U256 = U256::max_value();
    left / target.clone()
}

#[test]
fn test_target_to_difficulty() {
    let data_vec: Vec<U256> = vec![
        u256!("0x64"),
        u256!("0x647891af"),
        u256!("0x7602337766ffeea09d64"),
        u256!("0x6224"),
        u256!("0x1"),
        u256!("0x2"),
        u256!("0x3"),
    ];

    for data in data_vec {
        dbg!(format!("{}", target_to_difficulty(&data)));
        dbg!(format!("{}", my_func_todifficulty(&data)));
    }
}

#[test]
fn test_div() {
    fn div(a: u32, b: u32) -> u32 {
        if a % b == b - 1 {
            a / b + 1
        } else {
            a / b
        }
    }

    let x = 17900007u32;
    let y = x - 1;
    for i in 1..999 {
        assert_eq!(x / i, div(y, i));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ckb_hash::blake2b_256;
    #[test]
    fn test_pow_message() {
        let zero_hash = blake2b_256(&[]).pack();
        let nonce = u128::max_value();
        let message = pow_message(&zero_hash, nonce);
        assert_eq!(
            message.to_vec(),
            [
                68, 244, 198, 151, 68, 213, 248, 197, 93, 100, 32, 98, 148, 157, 202, 228, 155,
                196, 231, 239, 67, 211, 136, 197, 161, 47, 66, 181, 99, 61, 22, 62, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
            ]
            .to_vec()
        );
    }
}
