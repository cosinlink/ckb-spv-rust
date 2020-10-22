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
    CKBTxProof, JsonMerkleProof, MergeByte32, TransactionProof, MAINNET_RPC_URL,
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

pub fn generate_ckb_single_tx_proof(tx_hash: H256) -> Result<CKBTxProof, String> {
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

    // tx_merkle_index means the tx index in transactions merkle tree of the block
    Ok(CKBTxProof {
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
