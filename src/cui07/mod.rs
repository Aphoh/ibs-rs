//! Cui (2007) Efficient Identity-based Signature Scheme 
//! [here](https://iacr.org/archive/pkc2004/29470275/29470275.pdf)
//! Note that the user public key lives in G2 instead of G1, and the TA public key lives in G1
//! instead of G2

use amcl_wrapper::{extension_field_gt::GT, field_elem::FieldElement, group_elem::GroupElement, group_elem_g1::G1, group_elem_g2::G2};
use rand::{CryptoRng, RngCore};

use crate::hash_to_scalar;

pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (FieldElement, G1, GT) {
    let ta_secret = FieldElement::random_using_rng(rng);
    let ta_pub = G1::generator().scalar_mul_const_time(&ta_secret);
    (ta_secret, ta_pub, GT::ate_pairing(&G1::generator(), &G2::generator()))
}

pub fn extract<B: AsRef<[u8]>>(identity: B, ta_secret: &FieldElement) -> (G2, FieldElement) {
    let id_field = hash_to_scalar(identity);
    let fact = (ta_secret + id_field.clone()).inverse();
    (fact * G2::generator(), id_field)
}


fn hash_msg_gt_to_scalar<M: AsRef<[u8]>>(message: M, r: &GT) -> FieldElement {
    let mut mr = r.to_bytes();
    mr.extend_from_slice(message.as_ref());
    hash_to_scalar(&mr)
}

#[allow(clippy::many_single_char_names)]
pub fn sign<M: AsRef<[u8]>>(message: M, s: &FieldElement, w: &GT, user_secret: &G2) -> (GT, G2) {
    let r = w.pow(s);
    let u = hash_msg_gt_to_scalar(message, &r);
    let v = (u + s) * user_secret;
    (r, v)
}


pub fn verify<M: AsRef<[u8]>>(message: M, r: &GT, v: &G2, id_field: &FieldElement, ta_pub_key: &G1, w: &GT) -> bool {
    let u = hash_msg_gt_to_scalar(message, r);
    let lhs = w.pow(&u)*r;
    let lhp = ta_pub_key + (id_field * G1::generator());
    let rhs = GT::ate_pairing(&lhp, v);
    lhs == rhs
}


#[cfg(test)]
mod tests {
    use super::*;
    const MSG: &str = "Message";
    const IDENT: &str = "Duncan Edwards";

    #[test]
    fn test_correctness() {
        let (ta_secret, ta_pub_key, w) = setup(&mut rand::thread_rng());
        let (user_secret, id_field) = extract(IDENT, &ta_secret);

        let s = hash_to_scalar("Random scalar");
        let (r_sig, v_sig) = sign(MSG, &s, &w, &user_secret);

        assert!(verify(MSG, &r_sig, &v_sig, &id_field, &ta_pub_key, &w));
        assert!(!verify("Incorrect message", &r_sig, &v_sig, &id_field, &ta_pub_key, &w));
        assert!(!verify("Incorrect message", &r_sig, &v_sig, &FieldElement::random(), &ta_pub_key, &w));
    }
}
