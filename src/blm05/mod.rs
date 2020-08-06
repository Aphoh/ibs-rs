//! BLM05 Identity-Based Signature Scheme, as documented
//! [here](https://link.springer.com/content/pdf/10.1007%2F11593447_28.pdf)

use super::*;
use rand::{CryptoRng, RngCore};

pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (FieldElement, G2, GT) {
    let ta_secret = FieldElement::random_using_rng(rng);
    let ta_pub = G2::generator().scalar_mul_const_time(&ta_secret);
    (
        ta_secret,
        ta_pub,
        GT::ate_pairing(&G1::generator(), &G2::generator()),
    )
}

pub fn extract<B: AsRef<[u8]>>(identity: B, ta_secret: &FieldElement) -> G1 {
    (hash_to_scalar(identity) + ta_secret).inverse() * G1::generator()
}

pub fn sign<M: AsRef<[u8]>>(
    message: M,
    x: &FieldElement,
    g: &GT,
    user_secret: &G1,
) -> (FieldElement, G1) {
    let r: GT = g.pow(x);
    let h = hash_to_scalar([message.as_ref(), r.to_bytes().as_ref()].concat());
    let s = (x + &h) * user_secret;

    (h, s)
}

pub fn verify<M: AsRef<[u8]>, B: AsRef<[u8]>>(
    message: M,
    h: &FieldElement,
    s: &G1,
    identity: B,
    ta_pub_key: &G2,
    g: &GT,
) -> bool {
    let rh_pair = (hash_to_scalar(identity) * G2::generator()) + ta_pub_key;
    let pair: GT = GT::ate_pairing(s, &rh_pair) * g.pow(&h.negation());
    let h_test = hash_to_scalar([message.as_ref(), pair.to_bytes().as_ref()].concat());
    h_test.eq(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    const MSG: &str = "Message";
    const IDENT: &str = "Duncan Edwards";

    #[test]
    fn test_correctness() {
        let (ta_secret, ta_pub_key, g_const) = setup(&mut rand::thread_rng());
        let user_secret = extract(IDENT, &ta_secret);

        let x = hash_to_scalar("Random scalar");
        let (h, s) = sign(MSG, &x, &g_const, &user_secret);

        assert!(verify(MSG, &h, &s, IDENT, &ta_pub_key, &g_const));
    }
}
