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
    CkbHistoryTxRootProof, CkbTxProof, JsonMerkleProof, MergeByte32, TransactionProof,
    MAINNET_RPC_URL,
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

pub fn verify_ckb_history_tx_root_proof(
    tx_roots_proof: CkbHistoryTxRootProof,
) -> Result<H256, String> {
    let mut rpc_client = HttpRpcClient::new(MAINNET_RPC_URL.to_owned());
    let mut all_tx_roots: Vec<H256> = vec![];
    for number in tx_roots_proof.init_block_number..tx_roots_proof.latest_block_number + 1 {
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
    let expect_tx_roots = {
        let mut tmp: Vec<Byte32> = all_tx_roots.iter().map(|tx_root| tx_root.pack()).collect();
        CBMT::build_merkle_root(tmp.as_slice())
    };

    // calc transactions_root from tx_proof
    let mut queue = tx_roots_proof.proof_leaves.clone();
    let mut indices = tx_roots_proof.indices.clone();
    let mut queue_head = 0usize;
    let mut queue_tail = queue.len();

    // 确保 indices 是逆序的, 从高区块到低区块, proof_leaves 也按照这个顺序
    let mut node_sibling;
    let mut node_index;
    let mut next;
    let mut lemmas_index = 0;
    let mut res;
    let mut node = Default::default();
    let actual_history_tx_roots_root = {
        while queue_head < queue_tail {
            node = queue.get(queue_head).unwrap().clone();
            node_index = indices.get(queue_head).unwrap().clone();
            if node_index == 0 {
                break;
            }

            queue_head = queue_head + 1;

            next = indices.get(queue_head);
            if next.is_some() && next.unwrap().clone() == sibling(node_index) {
                node_sibling = queue.get(queue_head).unwrap().clone();
                queue_head = queue_head + 1;
            } else {
                if lemmas_index >= tx_roots_proof.lemmas.len() {
                    return Err(format!("proof invalid"));
                }
                node_sibling = tx_roots_proof.lemmas.get(lemmas_index).unwrap().clone();
                lemmas_index += 1;
            }

            res = if node_index < sibling(node_index) {
                // dbg!(node.pack().clone(), node_sibling.pack().clone());
                merge(node.pack(), node_sibling.pack())
            } else {
                // dbg!(node_sibling.pack().clone(), node.pack().clone());
                merge(node_sibling.pack(), node.pack())
            };

            // dbg!(res.clone());

            queue.push(res.unpack());
            indices.push(parent(node_index));
            queue_tail = queue_tail + 1;
        }
        node
    };

    if actual_history_tx_roots_root == expect_tx_roots.unpack() {
        return Ok(actual_history_tx_roots_root);
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
fn test_more_leaves() {
    use crate::proof_generator::generate_transaction_proof;
    let tx_hashes = vec![
        h256!("0x015aa60116ea60811207004edb1f4c6dfa4d23aad1467f629fda3a5de427c16b"),
        h256!("0x8532426af2da301143626bd292640ff63457beeadae9ab0a46ed254c7fafe62b"),
        h256!("0x83ae89de300b7ef46565f932a6a8ee425a67c3feab44aa725410e1ec099c506c"),
        h256!("0x7835c3761a71df3276e2d76b2643eea1866eccff8f7d83ea0116710904e18d6e"),
        h256!("0x39e33c8ad2e7e4eb71610d2bcdfbb0cb0fde2f96418256914ad2f5be1d6e9331"),
        h256!("0x2154d077a6af711d93e8c7f75e3281a64708f97c2d485e5ecafaae12bdeecd7c"),
    ];
    let proof = generate_transaction_proof(tx_hashes).unwrap();
    let result = verify_transaction_proof(proof).expect("proof should be verified");
    dbg!(format!("{:#x}", result[0].clone()));
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

#[test]
fn test_tx_roots_proof() {
    use crate::proof_generator::generate_ckb_history_tx_root_proof;
    let block_numbers = vec![1, 3, 5, 6, 9, 25];
    let tx_roots_proof = generate_ckb_history_tx_root_proof(1, 66, block_numbers).unwrap();
    dbg!(verify_ckb_history_tx_root_proof(tx_roots_proof));
}
