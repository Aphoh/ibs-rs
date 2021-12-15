pub(crate) use amcl_wrapper::{
    extension_field_gt::GT, field_elem::FieldElement, group_elem::GroupElement, group_elem_g1::G1,
    group_elem_g2::G2,
};

pub mod blm05;
pub mod hess03;
pub mod pat02;
pub mod cui07;

pub fn hash_to_scalar<B: AsRef<[u8]>>(bytes: B) -> FieldElement {
    FieldElement::from_msg_hash(bytes.as_ref())
}

pub fn hash_to_g1<B: AsRef<[u8]>>(bytes: B) -> G1 {
    G1::from_msg_hash(bytes.as_ref())
}

pub fn hash_to_g2<B: AsRef<[u8]>>(bytes: B) -> G2 {
    G2::from_msg_hash(bytes.as_ref())
}
