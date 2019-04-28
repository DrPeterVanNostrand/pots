//! An implementation of a stacked bipartite expander DAG.

use rand::rngs::OsRng;
use rand::seq::SliceRandom;

use crate::hasher::Hasher;

pub const IN_DEGREE: usize = 16;

pub type VertexLabel = Vec<u8>;

/// A mapping from each source in a bipartite expander to its corresponding
/// sinks.
#[derive(Clone, Debug)]
pub struct Edges(Vec<Vec<usize>>);

impl Edges {
    pub fn new_permutation(n: usize) -> Self {
        let mut rng = OsRng::new().expect("could not create OsRng");
        let mut indices: Vec<usize> = (0..n).collect();
        let mut edges: Vec<Vec<usize>> = vec![vec![]; n];

        for sink_index in 0..n {
            indices.shuffle(&mut rng);
            for source_index in &indices[..IN_DEGREE] {
                edges[*source_index].push(sink_index);
            }
        }

        for edges_from_source in edges.iter_mut() {
            edges_from_source.sort();
        }

        Edges(edges)
    }

    /// Returns the source indices that the sink index `vertex` is connected to.
    pub fn get_parents(&self, vertex: usize) -> Vec<usize> {
        let mut parents = vec![];
        let mut n_parents = 0;
        for (source_index, edges) in self.0.iter().enumerate() {
            if edges.contains(&vertex) {
                parents.push(source_index);
                n_parents += 1;
                if n_parents == IN_DEGREE {
                    break;
                }
            }
        }
        parents
    }

    fn n(&self) -> usize {
        self.0.len()
    }
}

/// A labeled graph.
#[derive(Debug)]
pub struct LabelMatrix(pub Vec<Vec<VertexLabel>>);

impl LabelMatrix {
    pub fn new(edges: &Edges, k: usize, nonce: &[u8]) -> Self {
        let n = edges.n();
        let mut label_matrix: Vec<Vec<VertexLabel>> = vec![vec![]; k];
        let mut hasher = Hasher::new();

        label_matrix[0] = (0..n)
            .map(|i| hasher.label_source(&nonce, i))
            .collect();

        for col in 1..k {
            for vertex in 0..n {
                let parent_labels: Vec<&VertexLabel> = edges
                    .get_parents(vertex)
                    .iter()
                    .map(|parent_index| &label_matrix[col - 1][*parent_index])
                    .collect();

                let vertex_label = hasher.label_non_source(&parent_labels);
                label_matrix[col].push(vertex_label);
            }
        }

        LabelMatrix(label_matrix)
    }
}

