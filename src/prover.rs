use crate::graph::{Edges, LabelMatrix};
use crate::merkle::{MerkleLabel, MerkleProof, MerkleTree};
use crate::params::ProtoParams;

#[derive(Debug)]
pub struct Prover {
    params: ProtoParams,
    edges: Edges,
    label_matrix: LabelMatrix,
    merkle_tree: MerkleTree,
}

impl Prover {
    pub fn new(params: ProtoParams, nonce: Vec<u8>) -> Self {
        let edges = Edges::new_permutation(params.n);
        let label_matrix = LabelMatrix::new(&edges, params.k, &nonce);
        let merkle_tree = MerkleTree::from_label_matrix(&label_matrix);
        Prover {
            params,
            edges,
            label_matrix,
            merkle_tree,
        }
    }

    pub fn edges(&self) -> &Edges {
        &self.edges
    }

    pub fn merkle_root(&self) -> &MerkleLabel {
        self.merkle_tree.root()
    }

    pub fn create_proofs(
        &mut self,
        challenge_indices: &[usize],
    ) -> Vec<MerkleProof> {
        challenge_indices
            .iter()
            .map(|challenge_index| self.create_proof(*challenge_index))
            .collect()
    }

    pub fn create_proof(&self, challenge_index: usize) -> MerkleProof {
        let path = self.merkle_tree.open(challenge_index);
        MerkleProof { challenge_index, path }

        /*
        let path = self.merkle_tree.open(challenge_index);
        let predecessors: Vec<(usize, MerklePath)> = self
            .get_predecessor_indices(challenge_index)
            .iter()
            .map(|index| (*index, self.merkle_tree.open(*index)))
            .collect();

        MerkleProof { challenge_index, path, predecessors }
        */
    }

    /*
    fn get_predecessor_indices(
        &self,
        index: usize,
    ) -> Vec<usize> {
        // Convert the unique index into a column and index.
        let col = index / self.params.n;
        let index = index % self.params.n;

        // Each `(usize, usize)` tuple represents a vertex at the matrix
        // position: (column, index).
        let mut queue: Vec<(usize, usize)> = vec![(col, index)];

        // The predessors of the `index` function argument. Each predecessor is
        // identified by its unique index.
        let mut pi: Vec<usize> = vec![];

        while let Some((col, index)) = queue.pop() {
            for parent_index in self.edges.get_parents(index) {
                let predecessor_index = col * self.params.n + parent_index;
                if !pi.contains(&predecessor_index) {
                    pi.push(predecessor_index);
                    queue.push((col - 1, parent_index));
                }
            }
        }

        pi
    }
    */
}
