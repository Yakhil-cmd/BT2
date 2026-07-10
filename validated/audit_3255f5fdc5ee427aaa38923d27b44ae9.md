### Title
`PresignOutput` Implements `Clone` Enabling Nonce Reuse Across Signing Sessions — (`src/ecdsa/ot_based_ecdsa/mod.rs`, `src/frost/eddsa/sign.rs`)

---

### Summary

Both the OT-based ECDSA and FROST EdDSA `PresignOutput` structs derive `Clone`, allowing callers to duplicate presign material and invoke the signing protocol multiple times with the same nonce. The library provides no enforcement mechanism to prevent this reuse. Nonce reuse in threshold ECDSA and FROST is a well-known catastrophic failure: it allows recovery of the participant's private key share from two observed signature shares produced under the same nonce.

---

### Finding Description

The OT-based ECDSA `PresignOutput` is defined as:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,      // nonce share
    pub sigma: Scalar,  // sigma share
}
``` [1](#0-0) 

The `Clone` derive means any caller holding a `PresignOutput` can produce an identical copy and pass it to `sign` (or `rerandomize_presign` + `sign`) a second time with a different message. The signing function itself takes `presignature: RerandomizedPresignOutput` by value, which looks like a single-use guarantee, but the upstream `PresignOutput` is cloneable before rerandomization, and `RerandomizedPresignOutput` also derives `Clone`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,
    pub sigma: Scalar,
}
``` [2](#0-1) 

The same pattern exists in FROST EdDSA `sign_v2`. The test suite explicitly clones `PresignOutput` to feed it into `sign_v2`:

```rust
sign_v2(
    participants,
    threshold,
    me,
    coordinator,
    keygen_output,
    presign_output.clone(),   // ← explicit clone of nonce material
    msg.clone(),
)
``` [3](#0-2) 

`do_sign_participant_v2` uses `presignature.nonces` directly without wrapping them in `Zeroizing`, unlike the v1 path which explicitly does `let nonces = Zeroizing::new(nonces)`:

```rust
let signature_share = round2::sign(&signing_package, &presignature.nonces, &key_package)
``` [4](#0-3) 

Compare with v1 coordinator and participant, which both zeroize:

```rust
let nonces = Zeroizing::new(nonces);
``` [5](#0-4) [6](#0-5) 

The library's own comment in `presign.rs` acknowledges the danger but provides no enforcement:

> "it's crucial that a presignature is never reused." [7](#0-6) 

---

### Impact Explanation

In threshold ECDSA, if the same nonce share `k_i` is used to produce two signature shares `s_i = h1·k_i + Rx·σ_i` and `s_i' = h2·k_i + Rx·σ_i` for messages `h1 ≠ h2`, an observer can solve for `k_i` and then recover `σ_i = (s_i - h1·k_i) / Rx`. With `σ_i` and the Lagrange coefficient, the private key share `x_i` is directly recoverable. The same algebraic argument applies to FROST nonce reuse. This maps to:

**Critical: Extraction, reconstruction, or disclosure of private signing shares.**

---

### Likelihood Explanation

The `Clone` bound is part of the public API surface. Any application layer that manages a pool of presign outputs (e.g., caching, retry logic, concurrent signing sessions, or serialization/deserialization round-trips) can inadvertently reuse the same nonce material. The library's own test suite demonstrates this pattern with `presign_output.clone()`. A malicious or buggy coordinator node that drives multiple signing rounds against the same presign pool is a realistic production scenario.

---

### Recommendation

1. **Remove `Clone` from `PresignOutput` and `RerandomizedPresignOutput`** in both `src/ecdsa/ot_based_ecdsa/mod.rs` and the FROST modules. Single-use semantics should be enforced by Rust's move semantics alone.
2. **Wrap `presignature.nonces` in `Zeroizing`** inside `do_sign_participant_v2` and `do_sign_coordinator_v2` in `src/frost/eddsa/sign.rs`, consistent with the v1 path.
3. If `Clone` must be retained for serialization purposes, add a runtime `used: AtomicBool` flag to `PresignOutput` and panic or return an error on second use.

---

### Proof of Concept

```
// Caller holds a PresignOutput from a completed presign round.
let presign: PresignOutput = run_presign(...);

// Sign message 1 — nonce k_i consumed logically, but Clone bypasses this.
let presign_copy = presign.clone();
let rerandomized1 = RerandomizedPresignOutput::rerandomize_presign(&presign, &args)?;
let proto1 = sign(participants, coordinator, threshold, me, pubkey, rerandomized1, hash1)?;
run_protocol(proto1); // produces s_i for hash1

// Sign message 2 — SAME nonce k_i reused.
let rerandomized2 = RerandomizedPresignOutput::rerandomize_presign(&presign_copy, &args)?;
let proto2 = sign(participants, coordinator, threshold, me, pubkey, rerandomized2, hash2)?;
run_protocol(proto2); // produces s_i' for hash2

// From (s_i, hash1) and (s_i', hash2) with the same k_i:
// k_i = (s_i - s_i') / (hash1 - hash2)
// x_i = (s_i - hash1 * k_i) / (Rx * lambda_i)
// Private key share x_i is fully recovered.
```

### Citations

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L40-49)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our share of the nonce value.
    pub k: Scalar,
    /// Our share of the sigma value.
    pub sigma: Scalar,
}
```

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L54-63)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our rerandomized share of the nonce value.
    pub k: Scalar,
    /// Our rerandomized share of the sigma value.
    pub sigma: Scalar,
}
```

**File:** src/frost/eddsa/sign.rs (L119-119)
```rust
    let nonces = Zeroizing::new(nonces);
```

**File:** src/frost/eddsa/sign.rs (L258-258)
```rust
    let nonces = Zeroizing::new(nonces);
```

**File:** src/frost/eddsa/sign.rs (L340-341)
```rust
    let signature_share = round2::sign(&signing_package, &presignature.nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
```

**File:** src/frost/eddsa/sign.rs (L583-596)
```rust
                let presign_output = presig
                    .iter()
                    .find(|(p, _)| p == &me)
                    .map(|(_, output)| output)
                    .unwrap();

                sign_v2(
                    participants,
                    threshold,
                    me,
                    coordinator,
                    keygen_output,
                    presign_output.clone(),
                    msg.clone(),
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L17-19)
```rust
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```
