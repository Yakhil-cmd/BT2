No vulnerability found for this question.

**Reasoning:**

The `DST` in `dekart_univariate_v2.rs` is a `const` associated with the `BatchedRangeProof` trait implementation, hardcoded as `b"APTOS_UNIVARIATE_DEKART_V2_RANGE_PROOF_DST"` [1](#0-0) . Both `prove()` and `verify()` (via `pairing_for_verify`) unconditionally construct the Fiat-Shamir transcript with `merlin::Transcript::new(Self::DST)`, using the compile-time constant, not a value taken from the `Proof` struct or any attacker-supplied input [2](#0-1) [3](#0-2) .

The `Proof<E>` struct itself has no DST field — it only contains `hat_C`, `pi_PoK`, `Cs`, `D`, `a`, `a_h`, `a_js`, `pi_gamma` [4](#0-3) . There is no code path by which an unprivileged attacker can inject an alternate DST string into `verify()`; the verifier always re-derives the transcript from its own hardcoded `Self::DST`, so a proof generated under a different/forked DST would simply fail to verify (as the proof's Fiat-Shamir-derived scalars `beta`/`gamma`/`mu` would not match what the verifier recomputes) — this is the correct, expected behavior, not a bypass.

Additionally, this code is not part of the transaction admission path (mempool, vm-validator, authenticator/WebAuthn/multisig checks) required by the boundary conditions — it is a standalone DKG range-proof primitive with no wiring shown into sender/signer/sequence/chain-id/expiry binding logic. No exploitable admission-bypass exists here.

### Citations

**File:** crates/aptos-dkg/src/range_proofs/dekart_univariate_v2.rs (L48-65)
```rust
pub struct Proof<E: Pairing> {
    /// ArkSize(E=Bls12_381): 48.
    hat_C: E::G1Affine,
    /// ArkSize(E=Bls12_381): 113.
    pi_PoK: sigma_protocol::Proof<E::ScalarField, two_term_msm::Homomorphism<E::G1>>,
    /// ArkSize(E=Bls12_381): 8 + 48·ell.
    Cs: Vec<E::G1Affine>,
    /// ArkSize(E=Bls12_381): 48.
    D: E::G1Affine,
    /// ArkSize(E=Bls12_381): 32.
    a: E::ScalarField,
    /// ArkSize(E=Bls12_381): 32.
    a_h: E::ScalarField,
    /// ArkSize(E=Bls12_381): 8 + 32·ell.
    a_js: Vec<E::ScalarField>,
    /// ArkSize(E=Bls12_381): 96.
    pi_gamma: univariate_hiding_kzg::OpeningProof<E>,
}
```

**File:** crates/aptos-dkg/src/range_proofs/dekart_univariate_v2.rs (L301-303)
```rust
    /// Domain-separation tag (DST) used to ensure that all cryptographic hashes and
    /// transcript operations within the protocol are uniquely namespaced
    const DST: &[u8] = b"APTOS_UNIVARIATE_DEKART_V2_RANGE_PROOF_DST";
```

**File:** crates/aptos-dkg/src/range_proofs/dekart_univariate_v2.rs (L493-493)
```rust
        let mut fs_t = merlin::Transcript::new(Self::DST);
```

**File:** crates/aptos-dkg/src/range_proofs/dekart_univariate_v2.rs (L908-908)
```rust
        let mut fs_t = merlin::Transcript::new(Self::DST);
```
