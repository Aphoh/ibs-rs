use ff::*;
use group::*;
use sodiumoxide::crypto::hash::sha256;
use pairing::bls12_381::{Bls12, G1, G2, Fr, Fq12, G1Affine, G2Affine};
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub mod hess03;

type Eng = Bls12;
pub type Gt = Fq12;

pub fn hash_to_scalar<B: AsRef<[u8]>>(bytes: B) -> Fr {
    let mut hash_state = sha256::State::new();
    hash_state.update(bytes.as_ref());
    //Fq::from_bytes_wide(&hash_state.finalize().0)
    Fr::random(&mut ChaCha20Rng::from_seed(hash_state.finalize().0))
}

pub fn hash_to_g1<B: AsRef<[u8]>>(bytes: B) -> G1 {
    let mut hash_state = sha256::State::new();
    hash_state.update(bytes.as_ref());
    //Fq::from_bytes_wide(&hash_state.finalize().0)
    G1::random(&mut ChaCha20Rng::from_seed(hash_state.finalize().0))
}

pub fn hash_to_g2<B: AsRef<[u8]>>(bytes: B) -> G2 {
    let mut hash_state = sha256::State::new();
    hash_state.update(bytes.as_ref());
    //Fq::from_bytes_wide(&hash_state.finalize().0)
    G2::random(&mut ChaCha20Rng::from_seed(hash_state.finalize().0))
}

pub fn gt_as_bytes(gt: Gt) -> Vec<u8> {
    // Not ideal eh?
    format!("{:?}", gt).into_bytes()
}

