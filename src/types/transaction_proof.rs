use ckb_types::{
    bytes::Bytes,
    core::{self, cell::CellProvider, TransactionBuilder},
    h256,
    packed::{self, Block, Byte32, Byte32Vec, Header, HeaderVec, ProposalShortId},
    prelude::*,
    utilities::{merkle_root, CBMT},
    H256,
};
use merkle_cbt::{merkle_tree::Merge, MerkleProof as ExMerkleProof, MerkleProof, CBMT as ExCBMT};
use serde::{Deserialize, Serialize};

use crate::types::generated::{basic, ckb_tx_proof};
use ckb_hash::new_blake2b;
use ckb_jsonrpc_types::Uint32;
use ckb_sdk::{
    rpc::{BlockView, RawHttpRpcClient, TransactionView, TransactionWithStatus},
    wallet::KeyStore,
    GenesisInfo, HttpRpcClient,
};
use std::collections::HashSet;

pub const MAINNET_RPC_URL: &str = "https://mainnet.ckb.dev";

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TransactionProof {
    pub block_hash: H256,
    pub witnesses_root: H256,
    pub proof: JsonMerkleProof,
}

// tx_merkle_index == index in transactions merkle tree of the block
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct CkbTxProof {
    pub tx_merkle_index: u16,
    pub block_number: u64,
    pub block_hash: H256,
    pub tx_hash: H256,
    pub witnesses_root: H256,
    pub lemmas: Vec<H256>,
}

// tx_merkle_index == index in transactions merkle tree of the block
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct CKBHistoryTxProof {
    pub block_number: u64,
    pub tx_merkle_index: u16,
    pub witnesses_root: H256,
    pub lemmas: Vec<H256>,
    pub raw_transaction: Bytes,
}

// tx_merkle_index == index in transactions merkle tree of the block
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct CKBHistoryTxRootProof {
    pub init_block_number: u64,
    pub latest_block_number: u64,
    pub indices: Vec<u64>,
    pub proof_leaves: Vec<H256>,
    pub lemmas: Vec<H256>,
}

// tx_merkle_index == index in transactions merkle tree of the block
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct CKBUnlockTokenParam {
    pub history_tx_root_proof: CKBHistoryTxRootProof,
    pub tx_proofs: Vec<CKBHistoryTxProof>,
}

impl From<packed::Bytes> for ckb_tx_proof::Bytes {
    fn from(data: packed::Bytes) -> Self {
        ckb_tx_proof::Bytes::from_slice(data.as_slice()).unwrap()
    }
}

impl From<CkbTxProof> for ckb_tx_proof::CkbTxProof {
    fn from(json: CkbTxProof) -> Self {
        let CkbTxProof {
            tx_merkle_index,
            block_number,
            block_hash,
            tx_hash,
            witnesses_root,
            lemmas,
        } = json;

        let mol_lemmas_vec: Vec<basic::Byte32> = lemmas
            .iter()
            .map(|hash| hash.pack().into())
            .collect::<Vec<_>>();

        let mol_lemmas = ckb_tx_proof::Byte32Vec::new_builder()
            .set(mol_lemmas_vec)
            .build();

        // basic to target
        //  impl From<basic> for target
        ckb_tx_proof::CkbTxProof::new_builder()
            .tx_merkle_index(tx_merkle_index.into())
            .block_number(block_number.into())
            .block_hash(block_hash.pack().into())
            .tx_hash(tx_hash.pack().into())
            .witnesses_root(witnesses_root.pack().into())
            .lemmas(mol_lemmas)
            .build()
    }
}

impl From<CKBHistoryTxProof> for ckb_tx_proof::CKBHistoryTxProof {
    fn from(json: CKBHistoryTxProof) -> Self {
        let CKBHistoryTxProof {
            block_number,
            tx_merkle_index,
            witnesses_root,
            lemmas,
            raw_transaction,
        } = json;

        let mol_lemmas_vec: Vec<basic::Byte32> = lemmas
            .iter()
            .map(|hash| hash.pack().into())
            .collect::<Vec<_>>();

        let mol_lemmas = ckb_tx_proof::Byte32Vec::new_builder()
            .set(mol_lemmas_vec)
            .build();

        let mol_raw_tx: ckb_tx_proof::Bytes =
            ckb_tx_proof::Bytes::new_unchecked(raw_transaction.to_vec().into());

        // basic to target
        //  impl From<basic> for target
        ckb_tx_proof::CKBHistoryTxProof::new_builder()
            .tx_merkle_index(tx_merkle_index.into())
            .block_number(block_number.into())
            .witnesses_root(witnesses_root.pack().into())
            .lemmas(mol_lemmas)
            .raw_transaction(mol_raw_tx)
            .build()
    }
}

impl From<CKBHistoryTxRootProof> for ckb_tx_proof::CKBHistoryTxRootProof {
    fn from(json: CKBHistoryTxRootProof) -> Self {
        let CKBHistoryTxRootProof {
            init_block_number,
            latest_block_number,
            indices,
            proof_leaves,
            lemmas,
        } = json;

        let mol_indices_vec: Vec<basic::Uint64> =
            indices.iter().map(|i| (*i).into()).collect::<Vec<_>>();

        let mol_indices = ckb_tx_proof::Uint64Vec::new_builder()
            .set(mol_indices_vec)
            .build();

        let mol_proof_leaves_vec: Vec<basic::Byte32> = proof_leaves
            .iter()
            .map(|hash| hash.pack().into())
            .collect::<Vec<_>>();

        let mol_proof_leaves = ckb_tx_proof::Byte32Vec::new_builder()
            .set(mol_proof_leaves_vec)
            .build();

        let mol_lemmas_vec: Vec<basic::Byte32> = lemmas
            .iter()
            .map(|hash| hash.pack().into())
            .collect::<Vec<_>>();

        let mol_lemmas = ckb_tx_proof::Byte32Vec::new_builder()
            .set(mol_lemmas_vec)
            .build();

        // basic to target
        //  impl From<basic> for target
        ckb_tx_proof::CKBHistoryTxRootProof::new_builder()
            .init_block_number(init_block_number.into())
            .latest_block_number(latest_block_number.into())
            .indices(mol_indices)
            .proof_leaves(mol_proof_leaves)
            .lemmas(mol_lemmas)
            .build()
    }
}

impl From<CKBUnlockTokenParam> for ckb_tx_proof::CKBUnlockTokenParam {
    fn from(json: CKBUnlockTokenParam) -> Self {
        let CKBUnlockTokenParam {
            history_tx_root_proof,
            tx_proofs,
        } = json;

        let mol_tx_proofs_vec: Vec<ckb_tx_proof::CKBHistoryTxProof> = tx_proofs
            .iter()
            .map(|tx_proof| tx_proof.clone().into())
            .collect();

        let mol_tx_proofs = ckb_tx_proof::CKBHistoryTxProofVec::new_builder()
            .set(mol_tx_proofs_vec)
            .build();

        // basic to target
        //  impl From<basic> for target
        ckb_tx_proof::CKBUnlockTokenParam::new_builder()
            .history_tx_root_proof(history_tx_root_proof.into())
            .tx_proofs(mol_tx_proofs)
            .build()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct JsonMerkleProof {
    pub indices: Vec<Uint32>,
    pub lemmas: Vec<H256>,
}

pub struct MergeByte32;

impl Merge for MergeByte32 {
    type Item = Byte32;
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let mut ret = [0u8; 32];
        let mut blake2b = new_blake2b();

        blake2b.update(left.as_slice());
        blake2b.update(right.as_slice());
        blake2b.finalize(&mut ret);
        ret.pack()
    }
}
