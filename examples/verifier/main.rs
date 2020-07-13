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
    let mut verifier = Verifier::new(
        DummyHasher {},
        vec![
            // Use the first byte (zero indexed) from the initialization vector.
            // If a third-party key generator is created for the app, simply change this
            // to another byte and forged keys won't work anymore.
            ByteCheck::new(0, (114, 83, 170)),
        ],
    );

    // Block a specific seed.
    // You might want to do this if the user requested a refund or a key was leaked.
    verifier.block(11111111_u64);

    // Verify a license key.
    let key = LicenseKey::parse::<HexFormat>("112210F4B2D230A229552341E723");
    match verifier.verify(&key) {
        Status::Valid => println!("Key is valid!"),
        Status::Invalid => println!("Key is invalid!"),
        Status::Blocked => println!("Key has been blocked!"),
        Status::Forged => println!("Key has been forged!"),
    }
}
