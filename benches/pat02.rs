use criterion::{criterion_group, criterion_main, Criterion};
use ibs_rs::pat02::*;
use ibs_rs::*;
use rand::Rng;

pub fn criterion_pat02(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let (ta_secret, ta_pub_key, g_const) = setup(&mut rand::thread_rng());

    let uid: [u8; 32] = rng.gen();
    let msg: [u8; 32] = rng.gen();
    let k_seed: [u8; 32] = rng.gen();
    let user_secret = extract(uid, &ta_secret);

    let k = hash_to_scalar(k_seed);
    c.bench_function("pat02 sign", |b| {
        b.iter(|| {
            sign(msg, &k, &user_secret);
        })
    });

    let (u_sig, v_sig) = sign(msg, &k, &user_secret);

    c.bench_function("pat02 method 1 verify", |b| {
        b.iter(|| verify_method_1(msg, &u_sig, &v_sig, uid, &ta_pub_key))
    });

    c.bench_function("pat02 method 2 verify", |b| {
        b.iter(|| verify_method_2(msg, &u_sig, &v_sig, uid, &ta_pub_key, &g_const))
    });
}

criterion_group!(benches, criterion_pat02);
criterion_main!(benches);
