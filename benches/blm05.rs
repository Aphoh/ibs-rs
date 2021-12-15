use criterion::{criterion_group, criterion_main, Criterion};
use ibs_rs::blm05::*;
use ibs_rs::*;
use rand::Rng;

pub fn criterion_blm05(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let (ta_secret, ta_pub_key, g_const) = setup(&mut rng);

    let uid: [u8; 32] = rng.gen();
    let msg: [u8; 32] = rng.gen();
    let x_seed: [u8; 32] = rng.gen();
    let user_secret = extract(uid, &ta_secret);

    let x = hash_to_scalar(x_seed);

    c.bench_function("blm05 sign", |b| {
        b.iter(|| {
            sign(msg, &x, &g_const, &user_secret);
        })
    });

    let (h, s) = sign(msg, &x, &g_const, &user_secret);

    c.bench_function("blm05 verify", |b| {
        b.iter(|| verify(msg, &h, &s, uid, &ta_pub_key, &g_const))
    });
}

criterion_group!(benches, criterion_blm05);
criterion_main!(benches);
