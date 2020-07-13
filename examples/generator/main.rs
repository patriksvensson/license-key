use license_key::*;

// Define a hasher that will hash the seed and a initialization vector.
// Don't use this one but implement something yourself.
struct DummyHasher {}
impl KeyHasher for DummyHasher {
    fn hash(&self, seed: u64, a: u64, b: u64, c: u64) -> u8 {
        ((seed ^ a ^ b ^ c) & 0xFF) as u8
    }
}

pub fn main() {
    // Create a license generator
    let generator = Generator::new(
        DummyHasher {},
        vec![(114, 83, 170), (60, 208, 27), (69, 14, 202), (61, 232, 54)],
    );

    // Generate a license key using a seed.
    // A seed is unique per license key, and could be a hash of an e-mail address or similar.
    // You can later block individual seeds during verification.
    let key = generator.generate(1234567891011121314_u64);

    // Write the key information to the console.
    println!("Generated key");
    println!("-------------");
    println!("{}", key.serialize::<HexFormat>());
}
