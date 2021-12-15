use criterion::{criterion_group, criterion_main, Criterion};
use ibs_rs::cui07::*;
use ibs_rs::*;
use rand::Rng;

#[allow(clippy::many_single_char_names)]
pub fn criterion_cui07(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let (ta_secret, ta_pub_key, w) = setup(&mut rng);

    let uid: [u8; 32] = rng.gen();
    let msg: [u8; 32] = rng.gen();
    let x_seed: [u8; 32] = rng.gen();
    let (user_secret, id_field) = extract(uid, &ta_secret);

    let s = hash_to_scalar(x_seed);

    c.bench_function("cui07 sign", |b| {
        b.iter(|| {
            sign(msg, &s, &w, &user_secret);
        })
    });

    let (r, v) = sign(msg, &s, &w, &user_secret);

    c.bench_function("cui07 verify", |b| {
        b.iter(|| verify(msg, &r, &v, &id_field, &ta_pub_key, &w))
    });
}

criterion_group!(benches, criterion_cui07);
criterion_main!(benches);
