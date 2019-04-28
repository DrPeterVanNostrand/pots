//! A wrapper around SHA3-256, the hash function used to label graph vertices
//! and Merkle nodes.

use sha3::{Digest, Sha3_256};

use crate::graph::VertexLabel;
use crate::merkle::MerkleLabel;

pub const DIGEST_LENGTH: usize = 256 / 8;

#[derive(Debug)]
pub struct Hasher(Sha3_256);

impl Hasher {
    pub fn new() -> Self {
        Hasher(Sha3_256::new())
    }

    pub fn digest(&mut self) -> Vec<u8> {
        self.0.result_reset().to_vec()
    }

    pub fn label_source(&mut self, nonce: &[u8], i: usize) -> VertexLabel {
        self.0.input(nonce);
        self.0.input(&i.to_be_bytes());
        self.digest()
    }

    pub fn label_non_source(
        &mut self,
        parent_labels: &[&VertexLabel],
    ) -> VertexLabel {
        for parent_label in parent_labels {
            self.0.input(parent_label);
        }
        self.digest()
    }

    pub fn label_merkle_node(
        &mut self,
        left_input: &MerkleLabel,
        right_input: &MerkleLabel,
    ) -> MerkleLabel {
        self.0.input(left_input);
        self.0.input(right_input);
        self.digest()
    }
}
