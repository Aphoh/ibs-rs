use sodiumoxide::crypto::hash;
use bls12_381::{Gt, Scalar, G1Projective, G2Projective};
use std::ops::Mul;

pub mod hess03;

pub fn hash_to_scalar<B: AsRef<[u8]>>(bytes: B) -> Scalar {
    let mut hash_state = hash::State::new();
    hash_state.update(bytes.as_ref());
    Scalar::from_bytes_wide(&hash_state.finalize().0)
}

pub fn gt_as_bytes(gt: Gt) -> Vec<u8> {
    // Not ideal eh?
    format!("{:?}", gt).into_bytes()
}

pub fn hash_to_g1<B: AsRef<[u8]>>(bytes: B) -> G1Projective {
    G1Projective::generator().mul(hash_to_scalar(bytes))
}

pub fn hash_to_g2<B: AsRef<[u8]>>(bytes: B) -> G2Projective {
    G2Projective::generator().mul(hash_to_scalar(bytes))
}
