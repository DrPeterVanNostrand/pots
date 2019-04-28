mod graph;
mod hasher;
mod merkle;
mod params;
mod prover;
mod utils;
mod verifier;

use wasm_bindgen::prelude::*;

use params::{ProtoParams, Space};
use prover::Prover;
use utils::set_panic_hook;
use verifier::Verifier;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

#[wasm_bindgen]
pub fn main() {
    set_panic_hook();

    let params = ProtoParams::new(Space::Kbs(4));
    let nonce = vec![];

    log(&format!("{:#?}", params));

    let mut verifier = Verifier::new(params.clone(), nonce);
    let mut prover = Prover::new(params, verifier.nonce().to_vec());
    let graph_edges = prover.edges().clone();
    let graph_commit = prover.merkle_root().to_vec();
    verifier.set_graph_description(graph_edges, graph_commit);
    let challenge_vertices = verifier.gen_challenge();
    let proofs = prover.create_proofs(&challenge_vertices);
    let verification_res = verifier.verify_proofs(&proofs);

    log(&format!("res => {:?}", verification_res));
}
