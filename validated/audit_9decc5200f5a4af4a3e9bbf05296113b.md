[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** crates/aptos-crypto/src/slh_dsa_sha2_128s/slh_dsa_sigs.rs (L61-68)
```rust
impl SignatureTrait for Signature {
    type SigningKeyMaterial = PrivateKey;
    type VerifyingKeyMaterial = PublicKey;

    /// Verifies that the provided signature is valid for the provided message.
    fn verify<T: CryptoHash + Serialize>(&self, message: &T, public_key: &PublicKey) -> Result<()> {
        Self::verify_arbitrary_msg(self, &signing_message(message)?, public_key)
    }
```

**File:** crates/aptos-crypto/src/slh_dsa_sha2_128s/slh_dsa_sigs.rs (L70-77)
```rust
    /// Checks that `self` is valid for an arbitrary &[u8] `message` using `public_key`.
    /// Outside of this crate, this particular function should only be used for native signature
    /// verification in Move.
    fn verify_arbitrary_msg(&self, message: &[u8], public_key: &PublicKey) -> Result<()> {
        use slh_dsa::signature::Verifier;
        Verifier::<SlhDsaSignature<Sha2_128s>>::verify(&public_key.0, message, &self.0)
            .map_err(|e| anyhow!("SLH-DSA signature verification failed: {}", e))
    }
```

**File:** crates/aptos-crypto/src/slh_dsa_sha2_128s/slh_dsa_keys.rs (L360-378)
```rust
        // Sign the message
        let signature = key.sign_arbitrary_message(test_message);

        // Verify the signature
        assert!(
            signature
                .verify_arbitrary_msg(test_message, &pubkey)
                .is_ok(),
            "Generated key should produce valid signatures"
        );

        // Verify wrong message fails
        assert!(
            signature
                .verify_arbitrary_msg(b"wrong message", &pubkey)
                .is_err(),
            "Signature should not verify for wrong message"
        );
    }
```
