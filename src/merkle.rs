use crate::graph::{LabelMatrix, VertexLabel};
use crate::hasher::Hasher;

pub type MerkleLabel = Vec<u8>;

pub type MerklePath = Vec<MerkleLabel>;

/// Given a vertex's index within a Merkle Tree layer, this function returns
/// `true` if the vertex is the left input for a child node.
pub fn is_left(index_within_layer: usize) -> bool {
    index_within_layer % 2 == 0
}

/// The Prover creates a `MerkleProof` for each vertex in the Verifier's
/// challenge set.
#[derive(Debug, Default)]
pub struct MerkleProof {
    pub challenge_index: usize,
    pub path: MerklePath,
}

#[derive(Debug)]
pub struct MerkleTree(Vec<Vec<MerkleLabel>>);

impl MerkleTree {
    pub fn from_label_matrix(label_matrix: &LabelMatrix) -> Self {
        let mut leaves: Vec<VertexLabel> = label_matrix
            .0
            .iter()
            .flat_map(|col_labels| col_labels.iter().cloned())
            .collect();

        let n_layers = {
            let n_leaves_init = leaves.len();
            let n_layers_init = (n_leaves_init as f32).log2();
            // If the number of leaves is not a power of two, add dataless
            // leaves until the number of leaves is a power of two.
            if n_layers_init.fract() != 0.0 {
                let n_layers_final = n_layers_init.trunc() + 1.0;
                let n_leaves_final = 2.0f32.powf(n_layers_final) as usize;
                leaves.resize(n_leaves_final, vec![]);
                n_layers_final as usize + 1
            } else {
                n_layers_init as usize + 1
            }
        };

        let mut hasher = Hasher::new();
        let mut tree = vec![leaves];

        for layer_index in 1..n_layers {
            let mut curr_layer = vec![];
            let prev_layer = &tree[layer_index - 1];
            for two_labels in prev_layer.chunks(2) {
                let left_input = &two_labels[0];
                let right_input = &two_labels[1];
                let merkle_label = hasher.label_merkle_node(
                    left_input,
                    right_input,
                );
                curr_layer.push(merkle_label);
            }
            tree.push(curr_layer);
        }

        MerkleTree(tree)
    }

    pub fn root(&self) -> &MerkleLabel {
        &self.0.last().unwrap()[0]
    }

    fn n_layers(&self) -> usize {
        self.0.len()
    }

    #[allow(dead_code)]
    fn n_leaves(&self) -> usize {
        self.0[0].len()
    }

    pub fn open(&self, vertex_index: usize) -> MerklePath {
        let mut path = vec![];
        let mut curr_index = vertex_index;
        let curr_merkle_label = self.0[0][curr_index].clone();
        path.push(curr_merkle_label);

        for layer_index in 0..(self.n_layers() - 1) {
            let sibling_index = if curr_index % 2 == 0 {
                curr_index + 1
            } else {
                curr_index - 1
            };

            let sibling_merkle_label =
                self.0[layer_index][sibling_index].clone();

            path.push(sibling_merkle_label);

            // Get the index of the child node in the next layer.
            let child_index = (curr_index as f32 / 2.0).floor() as usize;
            curr_index = child_index;
        }

        path.push(self.root().to_vec());
        path
    }
}
