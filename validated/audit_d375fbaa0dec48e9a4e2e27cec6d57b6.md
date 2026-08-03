[1](#0-0) [2](#0-1)

### Citations

**File:** types/src/keyless/mod.rs (L1-1)
```rust

```

**File:** types/src/transaction/authenticator.rs (L1412-1440)
```rust
    fn verify_keyless_ephemeral_signature<T: Serialize + CryptoHash>(
        message: &T,
        signature: &KeylessSignature,
    ) -> Result<()> {
        // Verifies the ephemeral signature on (TXN [+ ZKP]). The rest of the verification,
        // i.e., [ZKPoK of] OpenID signature verification is done in
        // `AptosVM::run_prologue`.
        //
        // This is because the JWK, under which the [ZKPoK of an] OpenID signature verifies,
        // can only be fetched from on chain inside the `AptosVM`.
        //
        // This deferred verification is what actually ensures the `signature.ephemeral_pubkey`
        // used below is the right pubkey signed by the OIDC provider.

        let mut txn_and_zkp = TransactionAndProof {
            message,
            proof: None,
        };

        // Add the ZK proof into the `txn_and_zkp` struct, if we are in the ZK path
        match &signature.cert {
            EphemeralCertificate::ZeroKnowledgeSig(proof) => txn_and_zkp.proof = Some(proof.proof),
            EphemeralCertificate::OpenIdSig(_) => {},
        }

        signature
            .ephemeral_signature
            .verify(&txn_and_zkp, &signature.ephemeral_pubkey)
    }
```
