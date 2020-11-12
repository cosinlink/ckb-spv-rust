use ckb_types::{
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

// CKBChain   CkbTxProof
// TokenLocker  unlockToken( CkbTxProof, RawTransaction + funding_input_index + extra )
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
