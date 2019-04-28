//! Derivation of protocol parameters from the Verifier's space requirement.

use crate::hasher::DIGEST_LENGTH;

/// The minimum number of vertices per disjoint set in the graph. We use a
/// constant in-degree of 16.
const MIN_N: usize = 16;

/// The number of columns in the graph.
const K: usize = 6;

/// The minimum ammout of proveable space for the given security
/// parameter `k` and label length.
///
/// Derivation:
/// `N_min = N_graph + N_merkle_tree`
/// `N_min = nkL + 2nL`
/// `N_min = nL(k + 2)`
///
/// Using `k = 6`, the minimum space requirement is 4kb.
const MIN_SPACE: usize = MIN_N * DIGEST_LENGTH * (K + 2);

/// The Verfier's space requirement.
#[allow(dead_code)]
#[derive(Debug)]
pub enum Space {
    Bytes(usize),
    Kbs(usize),
    Mbs(usize),
    Gbs(usize),
}

impl Space {
    pub fn n_bytes(&self) -> usize {
        match self {
            Space::Bytes(n_bytes) => *n_bytes,
            Space::Kbs(n_kbs) => n_kbs * 1024,
            Space::Mbs(n_mbs) => n_mbs * 1_048_576,
            Space::Gbs(n_gbs) => n_gbs * 1_073_741_824,
        }
    }
}

/// Calculates the number of vertices per disoint set (i.e. the number of
/// vertices per column in the graph).
///
/// Derivation:
///
/// `N = N_graph + N_merkle_tree`
/// `N = nkL + 2nL`
/// `N = nkL + 2nL`
/// `N = n(kL + 2L)`
/// `N / (Lk + 2L) = n`
/// `N / L(k + 2)  = n`
fn calc_n(space: usize) -> usize {
    let space = space as f32;
    let digest_length = DIGEST_LENGTH as f32;
    let k = K as f32;
    (space / (digest_length * (k + 2.0))).ceil() as usize
}

/// Minimizing delta allows us to keep our challenge size small. We minimize
/// delta using the inequality: `n - n/delta > n/4`.
fn calc_min_delta(n: usize) -> f32 {
    let n = n as f32;
    let mut delta = n;
    loop {
        delta -= 1.0;
        if n - n / delta < n / 4.0 {
            break;
        }
    }
    loop {
        delta += 0.01;
        if n - n / delta > n / 4.0 {
            return delta;
        }
    }
}

/// Calculates the length of the initial challenge set for a properly selected
/// `delta`: `l0 = Ln(2) * delta * k^2`.
fn calc_l0(k: usize, delta: f32) -> usize {
    let ln2 = 2.0f32.ln();
    let k_pow_2 = k.pow(2) as f32;
    (ln2 * delta * k_pow_2).ceil() as usize
}

/// The Proof-of-Space protocol parameters.
#[derive(Clone, Debug)]
pub struct ProtoParams {
    pub space: usize,
    pub n: usize,
    pub k: usize,
    pub delta: f32,
    pub l0: usize,
}

impl ProtoParams {
    pub fn new(space: Space) -> Self {
        let space = space.n_bytes();

        if space < MIN_SPACE {
            panic!("space requirement is too small");
        }

        let n = calc_n(space);
        let delta = calc_min_delta(n);
        let l0 = calc_l0(K, delta);

        ProtoParams {
            space,
            n,
            k: K,
            delta,
            l0,
        }
    }
}

/*
mod pops {
    /// The number of vertices per disjoint set in the graph (i.e. the number of
    /// vertices per column in each stacked bipartite expander).
    ///
    /// For a Proof of Persistant Storage, the audit phase requires that a
    /// honest Prover has space: `N = 2nL`.
    fn calc_n(space: usize) -> usize {
        let space = space as f32;
        let label_length = DIGEST_LENGTH as f32;
        let n = space / (2.0 * label_length);
        n as usize
    }

    /// The minimum delta is always 1.35.
    fn calc_min_delta(n: usize) -> f32 {
        let n = n as f32;
        let major_step = 1.0f32;
        let minor_step = 0.05f32;
        let mut delta = n;

        loop {
            delta -= major_step;
            if (n - n / delta) < n / 4.0 {
                break;
            }
        }

        loop {
            delta += minor_step;
            if (n - n / delta) > n / 4.0 {
                // Round up to the nearest hundreth.
                let tmp = delta * 100.0;
                if tmp.fract() == 0.0 {
                    return delta;
                } else {
                    return tmp.ceil() / 100.0;
                }
            }
        }
    }

    fn calc_max_k(n: usize, delta: f32) -> usize {
        let mut k = 2;
        loop {
            k += 1;
            let l0 = calc_l0(k, delta);
            let n_total = n * k;
            if l0 > n_total {
                return k - 1;
            }
        }
    }

    /// Calculates the length of the challenge set for the audit phase.
    fn calc_l1(k: usize) -> usize {
        (k as f32 / 2.0).ceil() as usize
    }

    #[derive(Clone, Debug)]
    pub struct ProtoParams {
        pub space: usize,
        pub n: usize,
        pub delta: f32,
        pub k: usize,
        pub l0: usize,
        pub l1: usize,
    }

    impl ProtoParams {
        pub fn new(space: Space) -> Self {
            let space = space.n_bytes();

            // The minimum space requirement (for the labeling function `Sha3_256`
            // and the minimum `n = 4`) is 1024 bytes: if `N = 2nL` and `L = 32`,
            // and `n_min = 16` (the in-degree is 16), then
            // `N_min = 2 * n_min * L = 1024`,
            if space < 1024 {
                panic!("space cannot be less than 1024 bytes");
            }

            let n = calc_n(space);
            let delta = calc_min_delta(n);
            let k = calc_max_k(n, delta);
            let l0 = calc_l0(k, delta);
            let l1 = calc_l1(k);

            ProtoParams {
                space,
                n,
                delta,
                k,
                l0,
                l1,
            }
        }
    }
}
*/
