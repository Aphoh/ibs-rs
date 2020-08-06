//! Hess03 Identity-Based Signature Scheme, as documented
//! [here](https://link.springer.com/chapter/10.1007/3-540-36492-7_20). A pdf is available
//! [here](https://link.springer.com/content/pdf/10.1007/3-540-36492-7_20.pdf)

use super::*;
use rand::{RngCore, CryptoRng};

pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (FieldElement, G2) {
    let ta_secret = FieldElement::random_using_rng(rng);
    let ta_pub = G2::generator().scalar_mul_const_time(&ta_secret);
    (ta_secret, ta_pub)
}

pub fn extract<B: AsRef<[u8]>>(identity: B, ta_secret: &FieldElement) -> G1 {
    hash_to_g1(identity.as_ref()).scalar_mul_const_time(ta_secret)
}

pub fn sign<M: AsRef<[u8]>>(
    message: M,
    p1: &G1,
    k: &FieldElement,
    user_secret: &G1,
) -> (G1, FieldElement) {
    let r: GT = GT::ate_pairing(p1, &G2::generator()).pow(k);
    let v = hash_to_scalar([message.as_ref(), r.to_bytes().as_ref()].concat());
    let u = G1::binary_scalar_mul(user_secret, p1, &v, k); //sid * v + p1 * k
    (u, v)
}

pub fn verify<M: AsRef<[u8]>, B: AsRef<[u8]>>(
    message: M,
    u: &G1,
    v: &FieldElement,
    identity: B,
    ta_pub_key: &G2,
) -> bool {
    let neg_ta_pk = ta_pub_key.negation();
    let v_uid = hash_to_g1(identity).scalar_mul_const_time(v);
    let r = GT::ate_2_pairing(u, &G2::generator(), &v_uid, &neg_ta_pk);
    let rhs = hash_to_scalar([message.as_ref(), r.to_bytes().as_ref()].concat());
    rhs.eq(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    const MSG: &str = "Message";
    const IDENT: &str = "Duncan Edwards";

    #[test]
    fn test_correctness() {
        let (ta_secret, ta_pub_key) = setup(&mut rand::thread_rng());
        let user_secret = extract(IDENT, &ta_secret);

        let p1 = hash_to_g1("Sample P1");
        let k = hash_to_scalar("Random scalar");
        let (u_sig, v_sig) = sign(MSG, &p1, &k, &user_secret);

        assert!(verify(MSG, &u_sig, &v_sig, IDENT, &ta_pub_key));
    }
}
