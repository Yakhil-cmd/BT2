No vulnerability found for this question.

**Analysis:** The `verify` function in `ProofOfPossession` calls BLST's standard BLS signature verification where the "message" being signed is exactly `pk.to_bytes()` [1](#0-0) . Since the PoP is created as `sk.privkey.sign(&pk_bytes, DST_BLS_POP_IN_G2, &[])` [2](#0-1) , the public key bytes are cryptographically bound into the signed message itself, not merely accompanying metadata.

For the same 96-byte PoP signature to `verify()` successfully against two distinct public keys, an attacker would need a single BLS signature that validates under two different messages (`pk1.to_bytes()` and `pk2.to_bytes()`) — this is precisely BLS signature existential forgery/unforgeability, which is infeasible under the standard co-CDH hardness assumption underlying BLS12-381 signatures (used with subgroup checks enabled via `pk_validate=true` and `sig_validate=true`) [3](#0-2) . This is a cryptographic hardness property of the underlying pairing-based signature scheme (delegated to the `blst` library), not a code-level binding defect in Aptos's PoP wrapper.

Additionally, this file is not on any transaction-admission path (mempool, vm-validator, authenticator parsing, or REST/BCS transaction input) — it's validator-consensus-key registration tooling, out of scope per the boundary conditions requiring the exploit to originate from unprivileged transaction/authenticator/API input and affect sender/signer/replay/domain binding at admission time.

### Citations

**File:** crates/aptos-crypto/src/bls12381/bls12381_pop.rs (L54-65)
```rust
    pub fn verify(&self, pk: &PublicKey) -> Result<()> {
        // CRYPTONOTE(Alin): We call the signature verification function with pk_validate set to true
        // since we do not necessarily trust the PK we deserialized over the network whose PoP we are
        // verifying here.
        let result = self.pop.verify(
            true,
            &pk.to_bytes(),
            DST_BLS_POP_IN_G2,
            &[],
            &pk.pubkey,
            true,
        );
```

**File:** crates/aptos-crypto/src/bls12381/bls12381_pop.rs (L94-102)
```rust
    pub fn create_with_pubkey(sk: &PrivateKey, pk: &PublicKey) -> ProofOfPossession {
        // CRYPTONOTE(Alin): The standard does not detail how the PK should be serialized for hashing purposes; we just do the obvious.
        let pk_bytes = pk.to_bytes();

        // CRYPTONOTE(Alin): We hash with DST_BLS_POP_IN_G2 as per https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#section-4.2.3
        ProofOfPossession {
            pop: sk.privkey.sign(&pk_bytes, DST_BLS_POP_IN_G2, &[]),
        }
    }
```
