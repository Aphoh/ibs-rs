//! Patterson (2002) Identity-Based Signature Scheme, as documented
//! [here](https://eprint.iacr.org/2002/004.pdf)
//! Note that the user public key lives in G2 instead of G1, and the TA public key lives in G1
//! instead of G2

use super::*;
use rand::{CryptoRng, RngCore};
use std::ops::Mul;

pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (FieldElement, G2, GT) {
    let ta_secret = FieldElement::random_using_rng(rng);
    let ta_pub = G2::generator().scalar_mul_const_time(&ta_secret);
    (ta_secret, ta_pub, GT::ate_pairing(&G1::generator(), &G2::generator()))
}

pub fn extract<B: AsRef<[u8]>>(identity: B, ta_secret: &FieldElement) -> G1 {
    hash_to_g1(identity.as_ref()).scalar_mul_const_time(ta_secret)
}

pub fn sign<M: AsRef<[u8]>>(message: M, k: &FieldElement, user_secret: &G1) -> (G2, G1) {
    let u = G2::generator().scalar_mul_const_time(k);
    let v = k.inverse()
        * ((G1::generator() * hash_to_scalar(message.as_ref()))
            + (user_secret * hash_to_scalar(u.to_bytes(false))));
    (u, v)
}

/// Verifies using `GT::ate_2_pairing` and multiplying `H_2(M)` by one of the generators, as well
/// as multiplying `H_3(R)` by the user public key before computation. This avoids exponentiation
/// in `GT`. Strangely, this is more efficient than the obvious method, used in `verify_method_2`.
pub fn verify_method_1<M, B>(message: M, u: &G2, v: &G1, identity: B, ta_pub_key: &G2) -> bool
where
    M: AsRef<[u8]>,
    B: AsRef<[u8]>,
{
    let uv_pair = GT::ate_pairing(v, u);

    let left_p1 = G1::generator() * hash_to_scalar(message);
    let user_pub = hash_to_g1(identity);
    let u_hash = hash_to_scalar(u.to_bytes(false));
    let right_p1 = user_pub * u_hash;
    let pair = GT::ate_2_pairing(&left_p1, &G2::generator(), &right_p1, ta_pub_key);

    pair == uv_pair
}

/// Verifies by using a precomputed `e(P, Q)` and exponentiating in GT, using the obvious methods
/// of computing
pub fn verify_method_2<M, B>(message: M, u: &G2, v: &G1, identity: B, ta_pub_key: &G2, g_const: &GT) -> bool
where
    M: AsRef<[u8]>,
    B: AsRef<[u8]>,
{
    let uv_pair = GT::ate_pairing(v, u);
    let u_hash = hash_to_scalar(u.to_bytes(false));

    let user_pub = hash_to_g1(identity);
    let rhs = g_const.pow(&hash_to_scalar(message)) * GT::ate_pairing(&user_pub, &ta_pub_key.mul(u_hash));

    rhs.eq(&uv_pair) 
}

#[cfg(test)]
mod tests {
    use super::*;
    const MSG: &str = "Message";
    const IDENT: &str = "Duncan Edwards";

    #[test]
    fn test_correctness_method_1() {
        let (ta_secret, ta_pub_key, _) = setup(&mut rand::thread_rng());
        let user_secret = extract(IDENT, &ta_secret);

        let k = hash_to_scalar("Random scalar");
        let (u_sig, v_sig) = sign(MSG, &k, &user_secret);

        assert!(verify_method_1(MSG, &u_sig, &v_sig, IDENT, &ta_pub_key));
        assert!(!verify_method_1(
            "Incorrect message",
            &u_sig,
            &v_sig,
            IDENT,
            &ta_pub_key
        ));
        assert!(!verify_method_1(
            MSG,
            &u_sig,
            &v_sig,
            "Incorrect Identity",
            &ta_pub_key
        ));
    }

    #[test]
    fn test_correctness_method_2() {
        let (ta_secret, ta_pub_key, g) = setup(&mut rand::thread_rng());
        let user_secret = extract(IDENT, &ta_secret);

        let k = hash_to_scalar("Random scalar");
        let (u_sig, v_sig) = sign(MSG, &k, &user_secret);

        assert!(verify_method_2(MSG, &u_sig, &v_sig, IDENT, &ta_pub_key, &g));
        assert!(!verify_method_2(
            "Incorrect message",
            &u_sig,
            &v_sig,
            IDENT,
            &ta_pub_key,
            &g
        ));
        assert!(!verify_method_2(
            MSG,
            &u_sig,
            &v_sig,
            "Incorrect Identity",
            &ta_pub_key,
            &g
        ));
    }
}
