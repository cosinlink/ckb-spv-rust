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
use crate::types::{JsonMerkleProof, MergeByte32, TransactionProof, MAINNET_RPC_URL};
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
fn test_wrong_block() {
    use crate::proof_generator::generate_transaction_proof;
    let tx_hash = h256!("0x02acc5ccc6073f371df6a89a6a1c22b567dbd1d82be2114c277d3f0f0cd07915");
    let mut proof = generate_transaction_proof(vec![tx_hash.clone()]).unwrap();

    // wrong block hash
    proof.block_hash = h256!("0xe2308e93e1ef1440cfce24c4474742e99406f05265932482d1489d657e975cd2");

    let result = verify_transaction_proof(proof);
    assert_eq!(Err(format!("Invalid transaction proof")), result)
}
