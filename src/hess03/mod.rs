//! Hess03 Identity based signature scheme, as documented
//! [here](https://link.springer.com/chapter/10.1007/3-540-36492-7_20). A pdf is available
//! [here](https://link.springer.com/content/pdf/10.1007/3-540-36492-7_20.pdf)


use super::*;
use pairing::Engine;
use pairing::bls12_381::{Fr, FrRepr, G1, G1Affine, G2, G2Affine, G2Prepared, Bls12};

pub fn setup() -> (Fr, G2) {
    let ta_secret = hash_to_scalar("TA Secret");
    let mut ta_pk = G2::one();
    ta_pk.mul_assign(ta_secret);
    (ta_secret, ta_pk)
}

pub fn extract<B: AsRef<[u8]>>(identity: B, ta_secret: Fr) -> G1 {
    let mut sid = hash_to_g1(identity.as_ref());
    sid.mul_assign(ta_secret);
    sid
}

pub fn sign<M: AsRef<[u8]>>(message: M, p1: &G1, k: &Fr, user_secret: &G1) -> (G1Affine, Fr) {
    let rpair = Bls12::pairing(p1.clone(), G2Affine::one());
    let repr: FrRepr = (*k).into();
    let r = rpair.pow(repr);
    let v = hash_to_scalar([message.as_ref(), gt_as_bytes(r).as_slice()].concat());
    let mut u = *user_secret;
    let mut p1_copy = *p1;
    u.mul_assign(v.clone());
    p1_copy.mul_assign(k.clone());
    u.add_assign(&p1_copy);
    (u.into(), v)
}

pub fn verify<M: AsRef<[u8]>, B: AsRef<[u8]>>(message: M, u: G1Affine, v: Fr, identity: B, neg_ta_pub_aff: G2Affine) -> bool {
    let user_pairing: Fq12 = Bls12::pairing(hash_to_g1(identity), neg_ta_pub_aff);
    let v_repr: FrRepr = v.into();
    user_pairing.pow(v_repr);
    let mut r = Bls12::pairing(u, G2Affine::one());
    r.add_assign(&user_pairing);
    v.eq(&hash_to_scalar([message.as_ref(), gt_as_bytes(r).as_slice()].concat()))
}

#[cfg(test)]
mod tests {
    use super::*;
    const MSG: &str = "Message";
    const IDENT: &str = "Duncan Edwards";

    #[test]
    fn test_correctness() {
        let (ta_secret, ta_pub_key) = setup();
        let user_secret = extract(IDENT, ta_secret); 

        let p1 = hash_to_g1("Sample P1");
        let k = hash_to_scalar("Random scalar");
        let (u_sig, v_sig) = sign(MSG, &p1.into(), &k, &user_secret);

        assert!(verify(MSG, u_sig, v_sig, IDENT, ta_pub_key.into()));
    }
}
