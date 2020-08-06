//! Hess03 Identity based signature scheme, as documented
//! [here](https://link.springer.com/chapter/10.1007/3-540-36492-7_20). A pdf is available
//! [here](https://link.springer.com/content/pdf/10.1007/3-540-36492-7_20.pdf)


use super::*;
use bls12_381::{Scalar, G1Projective, G1Affine, G2Projective, G2Affine, pairing};
use std::ops::{Neg, Add};

pub fn setup() -> (Scalar, G2Projective) {
    let ta_secret = hash_to_scalar("TA Secret");
    (ta_secret, G2Projective::generator().mul(ta_secret))
}

pub fn extract<B: AsRef<[u8]>>(identity: B, ta_secret: &Scalar) -> G1Projective {
    hash_to_g1(identity.as_ref()).mul(ta_secret) 
}

pub fn sign<M: AsRef<[u8]>>(message: M, p1: &G1Affine, k: &Scalar, user_secret: &G1Projective) -> (G1Affine, Scalar) {
    let r = pairing(&p1, &G2Affine::generator()).mul(k);
    let v = hash_to_scalar([message.as_ref(), gt_as_bytes(r).as_slice()].concat());
    let u = user_secret.mul(v) + p1.mul(k);
    (u.into(), v)
}

pub fn verify<M: AsRef<[u8]>, B: AsRef<[u8]>>(message: M, u: &G1Affine, v: &Scalar, identity: B, ta_pub: &G2Affine) -> bool {
    let user_pairing = pairing(&hash_to_g1(identity).into(), &ta_pub.neg());
    let r = pairing(u, &G2Affine::generator()).add(user_pairing.mul(v));
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
        let user_secret = extract(IDENT, &ta_secret); 

        let p1 = hash_to_g1("Sample P1");
        let k = hash_to_scalar("Random scalar");
        let (u_sig, v_sig) = sign(MSG, &p1.into(), &k, &user_secret);

        assert!(verify(MSG, &u_sig, &v_sig, IDENT, &ta_pub_key.into()));
    }
}
