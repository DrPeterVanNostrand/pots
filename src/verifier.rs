use rand::rngs::OsRng;
use rand::seq::SliceRandom;

use crate::graph::{Edges, VertexLabel};
use crate::hasher::Hasher;
use crate::merkle::{self, MerkleLabel, MerklePath, MerkleProof};
use crate::params::ProtoParams;

#[derive(Debug)]
pub enum VerificationError {
    CalculatedRootDoesNotMatchProof,
    CalculatedRootDoesNotMatchStoredRoot,
    InvalidNonSourceLabel,
    InvalidSourceLabel,
}

pub type VerificationResult = Result<(), VerificationError>;

#[derive(Debug)]
pub struct Verifier {
    params: ProtoParams,
    nonce: Vec<u8>,
    edges: Option<Edges>,
    merkle_root: Option<MerkleLabel>,
    rng: OsRng,
    hasher: Hasher,
    challenge: Vec<usize>,
}

impl Verifier {
    pub fn new(params: ProtoParams, nonce: Vec<u8>) -> Self {
        Verifier {
            params,
            nonce,
            edges: None,
            merkle_root: None,
            rng: OsRng::new().unwrap(),
            hasher: Hasher::new(),
            challenge: vec![],
        }
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    fn merkle_root(&self) -> &MerkleLabel {
        self.merkle_root.as_ref().unwrap()
    }

    fn edges(&self) -> &Edges {
        self.edges.as_ref().unwrap()
    }

    pub fn set_graph_description(
        &mut self,
        edges: Edges,
        merkle_root: MerkleLabel,
    ) {
        self.edges = Some(edges);
        self.merkle_root = Some(merkle_root);
    }

    pub fn gen_challenge(&mut self) -> Vec<usize> {
        let n_total = self.params.n * self.params.k;
        let mut indices: Vec<usize> = (0..n_total).collect();
        indices.shuffle(&mut self.rng);
        let challenge_indices: Vec<usize> = indices
            .iter()
            .take(self.params.l0)
            .cloned()
            .collect();
        self.challenge = challenge_indices.clone();
        challenge_indices
    }

    pub fn verify_proofs(
        &mut self,
        proofs: &[MerkleProof],
    ) -> VerificationResult {
        for proof in proofs.iter() {
            self.verify_proof(proof)?;
        }
        Ok(())
    }

    fn verify_proof(
        &mut self,
        proof: &MerkleProof,
    ) -> Result<(), VerificationError> {
        let MerkleProof { challenge_index, path } = proof;
        let challenge_is_source = challenge_index < &self.params.n;

        if challenge_is_source {
            let expected_challenge_label = self.hasher.label_source(
                &self.nonce,
                *challenge_index,
            );
            if path[0] != expected_challenge_label {
                return Err(VerificationError::InvalidSourceLabel);
            }
        } else {
            let expected_challenge_label = self.pebble_to(*challenge_index);
            if path[0] != expected_challenge_label {
                return Err(VerificationError::InvalidNonSourceLabel);
            }
        }

        self.verify_merkle_path(*challenge_index, &path)
    }

    fn verify_merkle_path(
        &mut self,
        index: usize,
        path: &MerklePath,
    ) -> Result<(), VerificationError> {
        // Hash together the leaf nodes to get their child node's label.
        let mut child_label = if merkle::is_left(index) {
            self.hasher.label_merkle_node(&path[0], &path[1])
        } else {
            self.hasher.label_merkle_node(&path[1], &path[0])
        };

        // The child node's index in the next layer of the Merkle tree.
        let mut child_index = index / 2;

        // Reconstruct the Merkle Tree then calculate its root.
        for sibling_label in &path[2..(path.len() - 1)] {
            child_label = if merkle::is_left(child_index) {
                self.hasher.label_merkle_node(&child_label, sibling_label)
            } else {
                self.hasher.label_merkle_node(sibling_label, &child_label)
            };
            child_index /= 2;
        }
        let calculated_root = child_label;

        if &calculated_root != self.merkle_root() {
            Err(VerificationError::CalculatedRootDoesNotMatchStoredRoot)
        } else if &calculated_root != path.last().unwrap() {
            Err(VerificationError::CalculatedRootDoesNotMatchProof)
        } else {
            Ok(())
        }
    }

    /// A memory efficient (one expander at a time) labeling of the graph up to
    /// and including the `dest` vertex. Returns the label of the `dest` vertex.
    fn pebble_to(&mut self, dest: usize) -> VertexLabel {
        let stop_col = dest / self.params.n;

        if stop_col == 0 {
            return self.hasher.label_source(&self.nonce, dest);
        }

        // Store one columns worth of labels at a time.
        let mut labels: Vec<VertexLabel> = (0..self.params.n)
            .map(|i| self.hasher.label_source(&self.nonce, i))
            .collect();

        // Pebble each column up to (but not including) `dest`'s column.
        for _ in 1..stop_col {
            labels = (0..self.params.n)
                .map(|i| {
                    let parent_labels: Vec<&VertexLabel> = self
                        .edges()
                        .get_parents(i)
                        .iter()
                        .map(|parent_index| &labels[*parent_index])
                        .collect();
                    self.hasher.label_non_source(&parent_labels)
                })
                .collect();
        }

        // Pebble `dest`.
        let index = dest % self.params.n;
        let parent_labels: Vec<&VertexLabel> = self
            .edges()
            .get_parents(index)
            .iter()
            .map(|parent_index| &labels[*parent_index])
            .collect();
        self.hasher.label_non_source(&parent_labels)
    }
}
