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

use crate::types::transaction_proof::{
    CKBHistoryTxProof, CKBHistoryTxRootProof, CkbTxProof, JsonMerkleProof, MergeByte32,
    TransactionProof, MAINNET_RPC_URL,
};
use ckb_jsonrpc_types::Uint32;
use ckb_sdk::{
    rpc::{BlockView, RawHttpRpcClient, TransactionView, TransactionWithStatus},
    wallet::KeyStore,
    GenesisInfo, HttpRpcClient,
};
use std::collections::HashSet;

pub fn calc_witnesses_root(transactions: Vec<TransactionView>) -> Byte32 {
    let leaves = transactions
        .iter()
        .map(|tx| {
            let tx: packed::Transaction = tx.clone().inner.into();
            tx.calc_witness_hash()
        })
        .collect::<Vec<Byte32>>();

    CBMT::build_merkle_root(leaves.as_ref())
}

pub fn get_tx_index(tx_hash: &H256, block: &BlockView) -> Option<usize> {
    block.transactions.iter().position(|tx| &tx.hash == tx_hash)
}

pub fn generate_transaction_proof(tx_hashes: Vec<H256>) -> Result<TransactionProof, String> {
    if tx_hashes.is_empty() {
        return Err(format!("Empty transaction hashes"));
    }

    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
    let mut retrieved_block_hash = None;
    let mut retrieved_block = Default::default();
    let mut tx_indices = HashSet::new();

    for tx_hash in tx_hashes {
        match rpc_client.get_transaction(tx_hash.clone())? {
            Some(tx_with_status) => {
                let tx_block_hash = tx_with_status.tx_status.block_hash;
                if retrieved_block_hash.is_none() {
                    retrieved_block_hash = tx_block_hash;
                    retrieved_block = rpc_client
                        .get_block(retrieved_block_hash.clone().expect("tx_block_hash is none"))?
                        .expect("block is none");
                } else if tx_block_hash != retrieved_block_hash {
                    return Err(format!("Not all transactions found in retrieved block",));
                }

                let tx_index = get_tx_index(&tx_hash, &retrieved_block)
                    .expect("tx_hash not in retrieved_block") as u32;
                dbg!(tx_index);
                if !tx_indices.insert(tx_index) {
                    return Err(format!("Duplicated tx_hash {:#x}", tx_hash));
                }
            }
            None => {
                return Err(format!(
                    "Transaction {:#x} not yet in block",
                    tx_hash.clone()
                ));
            }
        }
    }

    let retrieved_block_hash = retrieved_block_hash.expect("checked len");
    dbg!(format!("{:#x}", retrieved_block_hash));
    dbg!(format!("{:#x}", retrieved_block.header.hash));

    let proof = CBMT::build_merkle_proof(
        &retrieved_block
            .transactions
            .iter()
            .map(|tx| tx.hash.pack())
            .collect::<Vec<_>>(),
        &tx_indices.into_iter().collect::<Vec<_>>(),
    )
    .expect("build proof with verified inputs should be OK");

    Ok(TransactionProof {
        block_hash: retrieved_block_hash,
        witnesses_root: calc_witnesses_root(retrieved_block.transactions).unpack(),
        proof: JsonMerkleProof {
            indices: proof
                .indices()
                .iter()
                .map(|index| (*index).into())
                .collect(),
            lemmas: proof
                .lemmas()
                .iter()
                .map(|lemma| Unpack::<H256>::unpack(lemma))
                .collect(),
        },
    })
}

pub fn generate_ckb_single_tx_proof(tx_hash: H256) -> Result<CkbTxProof, String> {
    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
    let mut retrieved_block_hash = None;
    let mut retrieved_block = Default::default();
    let mut tx_indices = HashSet::new();
    let mut tx_index = 0;
    match rpc_client.get_transaction(tx_hash.clone())? {
        Some(tx_with_status) => {
            retrieved_block_hash = tx_with_status.tx_status.block_hash;
            retrieved_block = rpc_client
                .get_block(retrieved_block_hash.clone().expect("tx_block_hash is none"))?
                .expect("block is none");

            tx_index = get_tx_index(&tx_hash, &retrieved_block)
                .expect("tx_hash not in retrieved_block") as u32;
            dbg!(tx_index);
            if !tx_indices.insert(tx_index) {
                return Err(format!("Duplicated tx_hash {:#x}", tx_hash));
            }
        }
        None => {
            return Err(format!(
                "Transaction {:#x} not yet in block",
                tx_hash.clone()
            ));
        }
    }

    let tx_num = retrieved_block.transactions.len();
    let retrieved_block_hash = retrieved_block_hash.expect("checked len");
    dbg!(format!("{:#x}", retrieved_block_hash));
    dbg!(format!("{}", retrieved_block.header.inner.number));

    let proof = CBMT::build_merkle_proof(
        &retrieved_block
            .transactions
            .iter()
            .map(|tx| tx.hash.pack())
            .collect::<Vec<_>>(),
        &tx_indices.into_iter().collect::<Vec<_>>(),
    )
    .expect("build proof with verified inputs should be OK");

    // tx_merkle_index means the tx index in transactions merkle tree of the block
    Ok(CkbTxProof {
        block_hash: retrieved_block_hash,
        block_number: retrieved_block.header.inner.number,
        tx_hash: tx_hash.clone(),
        tx_merkle_index: (tx_index + tx_num as u32 - 1) as u16,
        witnesses_root: calc_witnesses_root(retrieved_block.transactions).unpack(),
        lemmas: proof
            .lemmas()
            .iter()
            .map(|lemma| Unpack::<H256>::unpack(lemma))
            .collect(),
    })
}

pub fn generate_history_tx_proof(tx_hash: H256) -> Result<CKBHistoryTxProof, String> {
    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
    let mut retrieved_block_hash = None;
    let mut retrieved_block = Default::default();
    let mut tx_indices = HashSet::new();
    let mut tx_index = 0;
    let mut raw_tx: packed::RawTransaction;
    match rpc_client.get_transaction(tx_hash.clone())? {
        Some(tx_with_status) => {
            retrieved_block_hash = tx_with_status.tx_status.block_hash;
            retrieved_block = rpc_client
                .get_block(retrieved_block_hash.clone().expect("tx_block_hash is none"))?
                .expect("block is none");

            tx_index = get_tx_index(&tx_hash, &retrieved_block)
                .expect("tx_hash not in retrieved_block") as u32;
            dbg!(tx_index);
            if !tx_indices.insert(tx_index) {
                return Err(format!("Duplicated tx_hash {:#x}", tx_hash));
            }
            let tx: packed::Transaction = tx_with_status.transaction.inner.into();
            raw_tx = tx.raw()
        }
        None => {
            return Err(format!(
                "Transaction {:#x} not yet in block",
                tx_hash.clone()
            ));
        }
    }

    let tx_num = retrieved_block.transactions.len();
    let retrieved_block_hash = retrieved_block_hash.expect("checked len");
    dbg!(format!("{:#x}", retrieved_block_hash));
    dbg!(format!("{}", retrieved_block.header.inner.number));

    let proof = CBMT::build_merkle_proof(
        &retrieved_block
            .transactions
            .iter()
            .map(|tx| tx.hash.pack())
            .collect::<Vec<_>>(),
        &tx_indices.into_iter().collect::<Vec<_>>(),
    )
    .expect("build proof with verified inputs should be OK");

    // tx_merkle_index means the tx index in transactions merkle tree of the block
    Ok(CKBHistoryTxProof {
        block_number: retrieved_block.header.inner.number,
        tx_merkle_index: (tx_index + tx_num as u32 - 1) as u16,
        witnesses_root: calc_witnesses_root(retrieved_block.transactions).unpack(),
        lemmas: proof
            .lemmas()
            .iter()
            .map(|lemma| Unpack::<H256>::unpack(lemma))
            .collect(),
        raw_transaction: raw_tx.as_bytes(),
    })
}

pub fn generate_ckb_history_tx_root_proof(
    init_block_number: u64,
    latest_block_number: u64,
    block_numbers: Vec<u64>,
) -> Result<CKBHistoryTxRootProof, String> {
    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
    let mut tx_roots_indices: Vec<u32> = vec![];
    let mut proof_leaves: Vec<H256> = vec![];
    let mut all_tx_roots: Vec<H256> = vec![];
    for number in init_block_number..latest_block_number + 1 {
        match rpc_client.get_header_by_number(number)? {
            Some(header_view) => all_tx_roots.push(header_view.inner.transactions_root),
            None => {
                return Err(format!(
                    "cannot get the block transactions root, block_number = {}",
                    number
                ));
            }
        }
    }

    for number in block_numbers {
        if number < init_block_number || number > latest_block_number {
            return Err(format!(
                "block number {} not yet between init_block_number {} and latest_block_number {}",
                number, init_block_number, latest_block_number
            ));
        }

        let index = (number - init_block_number) as u32;
        tx_roots_indices.push(index);
        proof_leaves.push(all_tx_roots.get(index as usize).unwrap().clone())
    }

    let tx_roots_num = latest_block_number - init_block_number + 1;
    // dbg!(format!("{:#x}", retrieved_block_hash));
    dbg!(format!("tx_roots_num: {}", tx_roots_num));

    let proof = CBMT::build_merkle_proof(
        &all_tx_roots
            .iter()
            .map(|tx_root| tx_root.pack())
            .collect::<Vec<_>>(),
        &tx_roots_indices.into_iter().collect::<Vec<_>>(),
    )
    .expect("build proof with verified inputs should be OK");

    let mut indices = proof.indices().to_vec();
    indices.sort_by(|a, b| b.cmp(a));
    proof_leaves.reverse();

    Ok(CKBHistoryTxRootProof {
        init_block_number,
        latest_block_number,
        indices: indices.iter().map(|i| *i as u64).collect(),
        proof_leaves,
        lemmas: proof
            .lemmas()
            .iter()
            .map(|lemma| Unpack::<H256>::unpack(lemma))
            .collect(),
    })
}
