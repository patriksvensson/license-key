/*!
A library for generating and verifying license keys without requiring
an Internet connection. For further protection, you can of course
validate the license key over the Internet.

# Features

* Does not require an Internet connection.
* Easy to revoke specific license keys in a software update.
* Not possible to disassemble an application to gain
  insight into how to generate a 100% working key since 
  the verification process doesn't check the whole license key.

For more information, read [`Implementing a Partial Serial Number Verification System in Delphi`]
by Brandon Staggs, which this crate was based upon.

# Anatomy of a license key

Every license key consists of a seed, a payload and a checksum.
Each byte in the payload is an operation of the seed and an
initialization vector. The 16-bit checksum is there to quickly check if
the key is valid at all, while the seed is a 64-bit hash of something
that identifies the license key owner such as an e-mail address or similar.  

The size of the payload depends on how big the initialization vector is.
In the example below, we are using a 5-byte intitialization vector which
results in a 5-byte payload.

```text
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│0x0│0x1│0x2│0x3│0x4│0x5│0x6│0x7│0x8│0x9│0xa│0xb│0xc│0xd│0xe│0xf│
├───┴───┴───┴───┴───┴───┴───┴───┴───┼───┴───┴───┴───┴───┼───┴───┤
│ SEED                              │ PAYLOAD           │ CHECK │
│                                   │                   │  SUM  │
└───────────────────────────────────┴───────────────────┴───────┘
```

# Generating a license key

```rust
use license_key::*;

// Define a hasher that will hash the seed and a initialization vector.
// DON'T USE THIS ONE. It's only for demonstrational purposes.
struct DummyHasher { }
impl KeyHasher for DummyHasher {
    fn hash(&self, seed: u64, a: u64, b: u64, c: u64) -> u8 {
        ((seed ^ a ^ b ^ c) & 0xFF) as u8
    }
}

// Create a license generator
// We use only four triplets in our initialization vector,
// but in a real world scenario you would want to use a lot more.
let generator = Generator::new(
    DummyHasher { },
    vec![
        // DON'T USE THIS ONE.
        // Generate your own.
        (114, 83, 170),
        (60, 208, 27),
        (69, 14, 202),
        (61, 232, 54)
     ],
);

// Generate a license key using a seed.
// A seed is unique per license key, and could be a hash of an e-mail address or similar.
// You can later block individual seeds during verification.
let key = generator.generate(1234567891011121314_u64);

// Write the key in hex format to the console.
// This will output something like: 112210F4B2D230A229552341B2E723
println!("{}", key.serialize::<HexFormat>());
```

# Verifying a license key

```rust
use license_key::*;

// Use the exact same hasher that we used when generating the key
struct DummyHasher { }
impl KeyHasher for DummyHasher {
    fn hash(&self, seed: u64, a: u64, b: u64, c: u64) -> u8 {
        ((seed ^ a ^ b ^ c) & 0xFF) as u8
    }
}

// Create the license key verifier
let mut verifier = Verifier::new(
    DummyHasher { },
    vec![
        // Use the first byte (zero indexed) from the initialization vector.
        // If a third-party key generator is created for the app, simply change this
        // to another byte and any forged keys won't work anymore.
        ByteCheck::new(0, (114, 83, 170)),
    ],
);

// Block a specific seed.
// You might want to do this if a key was leaked or the the 
// license key owner requested a refund.
verifier.block(11111111_u64);

// Parse a key in hex format
let key = LicenseKey::parse::<HexFormat>("112210F4B2D230A229552341E723");

// Verify the license key
match verifier.verify(&key) {
    Status::Valid => println!("Key is valid!"),
    Status::Invalid => println!("Key is invalid!"),
    Status::Blocked => println!("Key has been blocked!"),
    Status::Forged => println!("Key has been forged!"),
}
```

[`Implementing a Partial Serial Number Verification System in Delphi`]: 
https://www.brandonstaggs.com/2007/07/26/implementing-a-partial-serial-number-verification-system-in-delphi
*/

use std::convert::TryInto;

const SEED_BYTE_LENGTH: u8 = 8;
const CHECKSUM_BYTE_LENGTH: u8 = 2;
const SEGMENT_BYTE_LENGTH: u8 = 1;

/// Represent a hasher that turns the seed and a part of the
/// initialization vector into a license key byte.
pub trait KeyHasher {
    fn hash(&self, seed: u64, a: u64, b: u64, c: u64) -> u8;
}

/// Represents a license key serializer.
pub trait Serializer {
    /// Serializes a license key to a string.
    fn serialize(key: &LicenseKey) -> String;

    /// Deserializes a license key into a byte vector.
    fn deserialize(input: &str) -> Vec<u8>;
}

/// License key serializer for hex strings.
pub struct HexFormat {}
impl Serializer for HexFormat {
    fn serialize(key: &LicenseKey) -> String {
        hex::encode(key.get_bytes())
    }

    fn deserialize(input: &str) -> Vec<u8> {
        hex::decode(input).unwrap()
    }
}

/// Represents a generated or parsed license key.
#[derive(Debug, Clone)]
pub struct LicenseKey {
    bytes: Vec<u8>,
}

impl LicenseKey {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Deserializes a [`&str`] into a license key by using the
    /// provided [`Serializer`].
    ///
    /// [`&str`]: https://doc.rust-lang.org/std/primitive.str.html
    /// [`Serializer`]: trait.Serializer.html
    pub fn parse<T : Serializer>(input: &str) -> LicenseKey {
        LicenseKey::new(T::deserialize(input))
    }

    /// Serializes the license key into a [`String`] by using the 
    /// provided [`Serializer`].
    ///
    /// [`String`]: https://doc.rust-lang.org/std/string/struct.String.html
    /// [`Serializer`]: trait.Serializer.html
    pub fn serialize<T: Serializer>(&self) -> String {
        T::serialize(&self)
    }

    /// Gets the individual bytes that makes up the license key.
    pub fn get_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub(crate) fn get_byte(&self, ordinal: usize) -> Option<u8> {
        let index = SEED_BYTE_LENGTH as usize + (ordinal * SEGMENT_BYTE_LENGTH as usize);
        if index > self.bytes.len() - 3 {
            return None;
        }
        Some(self.bytes[index])
    }

    pub(crate) fn get_checksum(&self) -> &[u8] {
        &self.bytes[self.bytes.len() - CHECKSUM_BYTE_LENGTH as usize..]
    }

    pub(crate) fn get_seed(&self) -> u64 {
        u64::from_be_bytes(self.bytes[0..SEED_BYTE_LENGTH as usize].try_into().unwrap())
    }

    pub(crate) fn calculate_checksum(&self) -> [u8; 2] {
        calculate_checksum(&self.bytes[0..self.bytes.len() - CHECKSUM_BYTE_LENGTH as usize])
    }
}

/// The license key generator.
#[derive(Debug)]
pub struct Generator<T: KeyHasher> {
    hasher: T,
    iv: Vec<(u64, u64, u64)>,
}

impl<T: KeyHasher> Generator<T> {
    /// Creates a new license key generator.
    pub fn new(hasher: T, iv: Vec<(u64, u64, u64)>) -> Self {
        Self { hasher, iv }
    }

    /// Creates a new license key with the specified seed.
    pub fn generate(&self, seed: u64) -> LicenseKey {
        // Get the license key as a byte array
        let mut input = seed.to_be_bytes().to_vec();
        for iv in self.iv.iter() {
            for byte in self
                .hasher
                .hash(seed, iv.0, iv.1, iv.2)
                .to_be_bytes()
                .to_vec()
            {
                input.push(byte);
            }
        }

        // Calculate the checksum for the license key
        let checksum = calculate_checksum(&input);
        for byte in checksum.iter() {
            input.push(*byte);
        }

        LicenseKey::new(input)
    }
}

/// Representation of a license key status.
#[derive(Debug, PartialEq)]
pub enum Status {
    /// The license is valid.
    Valid,
    /// The license is invalid.
    Invalid,
    /// The license has been blocked.
    Blocked,
    /// The license has been forged.
    Forged,
}

/// Represents a license key byte check
/// that should be used during validation.
#[derive(Debug)]
pub struct ByteCheck {
    pub ordinal: u8,
    pub a: u64,
    pub b: u64,
    pub c: u64,
}

impl ByteCheck {
    /// Creates a new byte check.
    pub fn new(ordinal: u8, iv: (u64, u64, u64)) -> Self {
        Self {
            ordinal,
            a: iv.0,
            b: iv.1,
            c: iv.2,
        }
    }
}

/// The license key verifier.
#[derive(Debug)]
pub struct Verifier<T: KeyHasher> {
    hasher: T,
    checks: Vec<ByteCheck>,
    blocklist: Vec<u64>,
}

impl<T: KeyHasher> Verifier<T> {
    /// Creates a new license key verifier.
    pub fn new(hasher: T, checks: Vec<ByteCheck>) -> Self {
        Self {
            hasher,
            checks,
            blocklist: Vec::new(),
        }
    }

    /// Blocks the specified seed from being used.
    pub fn block(&mut self, seed: u64) {
        self.blocklist.push(seed)
    }

    /// Perform verification on the provided license key.
    pub fn verify(&self, key: &LicenseKey) -> Status {
        // Validate the checksum
        let checksum = key.calculate_checksum().to_vec();
        if checksum != key.get_checksum() {
            return Status::Invalid;
        }

        // Blocked key?
        let seed = key.get_seed();
        for blocked_seed in self.blocklist.iter() {
            if seed == *blocked_seed {
                return Status::Blocked;
            }
        }

        for check in self.checks.iter() {
            match key.get_byte(check.ordinal as usize) {
                Some(value) => {
                    if value != self.hasher.hash(seed, check.a, check.b, check.c) {
                        // Values did not match, but the checksum
                        // was correct, so this is a forged license key
                        return Status::Forged;
                    }
                }
                None => {
                    // If we couldn't get the byte from the license
                    // the license is invalid.
                    return Status::Invalid;
                }
            }
        }

        Status::Valid
    }
}

fn calculate_checksum(key: &[u8]) -> [u8; 2] {
    let mut left = 0x56_u16;
    let mut right = 0xAF_u16;

    for byte in key.iter() {
        right += *byte as u16;
        if right > 0xFF {
            right -= 0xFF;
        }
        left += right;
        if left > 0xFF {
            left -= 0xFF;
        }
    }
    ((left << 8) + right).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyHasher;
    use crate::Generator;

    #[derive(Default)]
    pub struct TestHasher {}
    impl KeyHasher for TestHasher {
        fn hash(&self, seed: u64, a: u64, b: u64, c: u64) -> u8 {
            ((seed ^ a ^ b ^ c) & 0xFF) as u8
        }
    }

    pub fn generate_key(seed: u64) -> LicenseKey {
        let generator = Generator::new(
            TestHasher::default(),
            vec![(114, 83, 170), (60, 208, 27), (69, 14, 202), (61, 232, 54)],
        );
        generator.generate(seed)
    }

    pub fn create_verifier() -> Verifier<TestHasher> {
        Verifier::new(
            TestHasher::default(),
            vec![
                ByteCheck::new(0, (114, 83, 170)),
                ByteCheck::new(2, (69, 14, 202)),
            ],
        )
    }

    #[test]
    pub fn valid_key_should_be_valid() {
        // Given
        let key = generate_key(12345);
        let verifier = create_verifier();

        // When
        let result = verifier.verify(&key);

        // Then
        assert_eq!(Status::Valid, result);
    }

    #[test]
    pub fn valid_but_blocked_key_should_return_error() {
        // Given
        let key = generate_key(12345);
        let mut verifier = create_verifier();
        verifier.block(12345);

        // When
        let result = verifier.verify(&key);

        // Then
        assert_eq!(Status::Blocked, result);
    }
}
