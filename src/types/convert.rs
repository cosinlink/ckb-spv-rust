use ckb_types::{
    core::{self, cell::CellProvider, TransactionBuilder},
    h256,
    packed::{self, Block, Header, ProposalShortId},
    prelude::*,
    utilities::{merkle_root, CBMT},
    H256,
};

use crate::types::generated::{
    basic::{Byte32, Uint16, Uint64},
    ckb_tx_proof::{self, Byte32Vec},
};

use crate::types::transaction_proof::CkbTxProof;
use molecule::{
    error::VerificationError,
    prelude::{Builder, Byte, Entity},
};

impl From<u64> for Uint64 {
    fn from(v: u64) -> Self {
        let mut inner = [Byte::new(0); 8];
        let v = v
            .to_le_bytes()
            .to_vec()
            .into_iter()
            .map(Byte::new)
            .collect::<Vec<_>>();
        inner.copy_from_slice(&v);
        Self::new_builder().set(inner).build()
    }
}

impl From<u16> for Uint16 {
    fn from(v: u16) -> Self {
        let mut inner = [Byte::new(0); 2];
        let v = v
            .to_le_bytes()
            .to_vec()
            .into_iter()
            .map(Byte::new)
            .collect::<Vec<_>>();
        inner.copy_from_slice(&v);
        Self::new_builder().set(inner).build()
    }
}

impl From<packed::Byte32> for Byte32 {
    fn from(v: packed::Byte32) -> Self {
        Self::new_unchecked(v.as_bytes())
    }
}

impl From<packed::Byte32Vec> for Byte32Vec {
    fn from(v: packed::Byte32Vec) -> Self {
        Self::new_unchecked(v.as_bytes())
    }
}
