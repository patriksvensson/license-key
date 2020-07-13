A library for generating and verifying license keys without requiring
an Internet connection. For further protection, you can of course
validate the license key over the Internet.

# Features

* Does not require an Internet connection.
* Easy to revoke specific license keys in a software update.
* Not possible to disassemble an application to gain
  insight into how to generate a 100% working key since 
  the verification process doesn't check the whole license key.

For more information, read 
[Implementing a Partial Serial Number Verification System in Delphi](https://www.brandonstaggs.com/2007/07/26/implementing-a-partial-serial-number-verification-system-in-delphi)
which this crate was based upon.

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