use criterion::{criterion_group, criterion_main, Criterion};
use license_key::*;

#[derive(Default)]
struct MyHasher {}
impl KeyHasher for MyHasher {
    fn hash(&self, seed: u64, a: u64, b: u64, c: u64) -> u8 {
        // For demonstrational purposes only.
        // You need to implement your own secret sauce.
        ((seed ^ a ^ b ^ c) & 0xFF) as u8
    }
}

fn generate_key(generator: &Generator<MyHasher>) {
    generator.generate(1235761289);
}

fn criterion_benchmark(c: &mut Criterion) {
    let generator = Generator::new(
        MyHasher::default(),
        vec![
            (112344, 812393, 175439050),
            (64234200, 223423408, 253485347),
            (653453459, 153454, 2534502),
            (675331, 23452, 553453454),
        ],
    );
    c.bench_function("generate_key", |b| b.iter(|| generate_key(&generator)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
