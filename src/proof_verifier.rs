use ckb_types::{
    core::{self, cell::CellProvider, TransactionBuilder},
    h256,
    packed::{self, Block, Byte32, Header, ProposalShortId},
    prelude::*,
    utilities::{merkle_root, CBMT},
    H256,
};
use merkle_cbt::{merkle_tree::Merge, MerkleProof as ExMerkleProof, MerkleProof, CBMT as ExCBMT};
use serde::{Deserialize, Serialize};

use crate::proof_generator::get_tx_index;
use crate::types::transaction_proof::{
    CkbTxProof, JsonMerkleProof, MergeByte32, TransactionProof, MAINNET_RPC_URL,
};
use ckb_hash::new_blake2b;
use ckb_jsonrpc_types::Uint32;
use ckb_sdk::{
    rpc::{BlockView, RawHttpRpcClient, TransactionView, TransactionWithStatus},
    wallet::KeyStore,
    GenesisInfo, HttpRpcClient,
};
use std::collections::HashSet;

pub fn calc_transactions_root(block: BlockView) -> Byte32 {
    let header_view: core::HeaderView = block.header.into();
    header_view.data().raw().transactions_root()
}

pub fn verify_transaction_proof(tx_proof: TransactionProof) -> Result<Vec<H256>, String> {
    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());

    let block = rpc_client
        .get_block(tx_proof.block_hash)?
        .expect("block is none");
    let witnesses_root = tx_proof.witnesses_root.pack();

    let merkle_proof: ExMerkleProof<_, MergeByte32> = ExMerkleProof::new(
        tx_proof
            .proof
            .indices
            .into_iter()
            .map(|index| index.value())
            .collect(),
        tx_proof
            .proof
            .lemmas
            .into_iter()
            .map(|lemma| lemma.pack())
            .collect(),
    );

    let block_tx_hashes = block
        .transactions
        .iter()
        .map(|tx| tx.hash.pack())
        .collect::<Vec<_>>();
    ExCBMT::retrieve_leaves(&block_tx_hashes, &merkle_proof)
        .and_then(|tx_hashes| {
            merkle_proof
                .root(&tx_hashes)
                .and_then(|raw_transactions_root| {
                    let transactions_root = calc_transactions_root(block);
                    dbg!(transactions_root.clone());
                    if transactions_root == merkle_root(&[raw_transactions_root, witnesses_root]) {
                        Some(tx_hashes.iter().map(|hash| hash.unpack()).collect())
                    } else {
                        None
                    }
                })
        })
        .ok_or_else(|| format!("Invalid transaction proof"))
}

pub fn sibling(input: u16) -> u16 {
    if input == 0 {
        return 0;
    }
    ((input + 1) ^ 1) - 1
}

pub fn parent(input: u16) -> u16 {
    if input == 0 {
        return 0;
    }
    (input - 1) >> 1
}

pub fn is_left(input: u16) -> bool {
    input & 1 == 1
}

pub fn merge(left: Byte32, right: Byte32) -> Byte32 {
    let mut ret = [0u8; 32];
    let mut blake2b = new_blake2b();

    blake2b.update(left.as_slice());
    blake2b.update(right.as_slice());
    blake2b.finalize(&mut ret);
    ret.pack()
}

pub fn verify_ckb_single_tx_proof(tx_proof: CkbTxProof) -> Result<H256, String> {
    let expected_transactions_root = {
        let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
        let block = rpc_client
            .get_block(tx_proof.block_hash)
            .unwrap()
            .expect("block is none");
        let header_view: core::HeaderView = block.header.into();

        // verify block number
        if header_view.number() != tx_proof.block_number {
            return Err(format!("block number and block hash mismatch"));
        }

        header_view.data().raw().transactions_root()
    };

    // calc transactions_root from tx_proof
    let witnesses_root = tx_proof.witnesses_root.pack();
    let raw_transactions_root = {
        let mut index = tx_proof.tx_merkle_index;
        let mut res = tx_proof.tx_hash.pack();
        let mut lemmas_index = 0;

        while lemmas_index < tx_proof.lemmas.len() {
            res = if index < sibling(index) {
                merge(res, tx_proof.lemmas[lemmas_index].pack())
            } else {
                merge(tx_proof.lemmas[lemmas_index].pack(), res)
            };

            lemmas_index += 1;
            index = parent(index)
        }

        res
    };

    if merkle_root(&[raw_transactions_root, witnesses_root]) == expected_transactions_root {
        return Ok(expected_transactions_root.unpack());
    }

    Err(format!("proof not verified"))
}

#[test]
fn test_correct() {
    use crate::proof_generator::generate_transaction_proof;
    let tx_hash = h256!("0x3827275f7a9785b09d85c2e687338a3dfb3978656747c2449685f31293210e2f");
    let proof = generate_transaction_proof(vec![tx_hash.clone()]).unwrap();
    let result = verify_transaction_proof(proof).expect("proof should be verified");
    dbg!(format!("{:#x}", result[0].clone()));
    assert_eq!(tx_hash, result[0]);
}

#[test]
fn test_correct_more() {
    use crate::proof_generator::generate_transaction_proof;
    let tx_hash = h256!("0x39e33c8ad2e7e4eb71610d2bcdfbb0cb0fde2f96418256914ad2f5be1d6e9331");
    let proof = generate_transaction_proof(vec![tx_hash.clone()]).unwrap();
    let result = verify_transaction_proof(proof).expect("proof should be verified");
    dbg!(format!("{:#x}", result[0].clone()));
    assert_eq!(tx_hash, result[0]);
}

#[test]
fn test_correct_single_tx_proof() {
    use crate::proof_generator::generate_ckb_single_tx_proof;
    let tx_hashes: Vec<H256> = vec![
        h256!("0x39e33c8ad2e7e4eb71610d2bcdfbb0cb0fde2f96418256914ad2f5be1d6e9331"),
        h256!("0x3827275f7a9785b09d85c2e687338a3dfb3978656747c2449685f31293210e2f"),
        h256!("0x02acc5ccc6073f371df6a89a6a1c22b567dbd1d82be2114c277d3f0f0cd07915"),
        h256!("0x5094be43fd4c45fdf9446d1f46d9ce0124af6d2b9cdaed21ff5840ad684f8a02"),
        h256!("0x0b332365bbdf1e7392af801e3f74496dfe94c22ac41e0e4b3924f352da5a3795"),
        h256!("0x55fbffa77f25fc53425f85d2fd7999b18a10bb55b3d70e9e61037a1138955c88"),
        h256!("0xce08d2fd4fe275ceddff74c8ae5d6ac27807b5c7788ed951c4f8e1ac507119a1"),
        h256!("0x477f3cce8c1a61d35056dec9e0e2ba135614ce93cca3f898fe702b9774ee4d76"),
    ];

    for tx_hash in tx_hashes {
        let mut proof = generate_ckb_single_tx_proof(tx_hash.clone()).unwrap();
        let result = verify_ckb_single_tx_proof(proof);
        assert!(result.is_ok());
    }
}

#[test]
fn test_to_solidity_use() {
    use crate::proof_generator::generate_ckb_single_tx_proof;
    let tx_hashes: Vec<H256> = vec![h256!(
        "0x39e33c8ad2e7e4eb71610d2bcdfbb0cb0fde2f96418256914ad2f5be1d6e9331"
    )];

    for tx_hash in tx_hashes {
        let mut proof = generate_ckb_single_tx_proof(tx_hash.clone()).unwrap();
        let result = verify_ckb_single_tx_proof(proof);
        assert_eq!(result.is_ok(), true);
    }
}

#[test]
fn test_wrong_block() {
    use crate::proof_generator::generate_transaction_proof;
    let tx_hash = h256!("0x02acc5ccc6073f371df6a89a6a1c22b567dbd1d82be2114c277d3f0f0cd07915");
    let mut proof = generate_transaction_proof(vec![tx_hash.clone()]).unwrap();

    // wrong block hash
    proof.block_hash = h256!("0xe2308e93e1ef1440cfce24c4474742e99406f05265932482d1489d657e975cd2");

    let result = verify_transaction_proof(proof);
    assert_eq!(Err(format!("Invalid transaction proof")), result)
}
