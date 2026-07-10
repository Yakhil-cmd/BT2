### Title
`PresignOutput` Derives `Clone` and `rerandomize_presign` Accepts `&PresignOutput` by Reference, Enabling Silent Presignature Reuse Leading to Private Key Extraction — (File: `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both OT-based and robust ECDSA `PresignOutput` types derive `Clone` (and `Serialize`/`Deserialize`), and `RerandomizedPresignOutput::rerandomize_presign` accepts the presignature as `&PresignOutput` — a shared reference that does **not** consume the value. The API therefore provides no type-level enforcement of the documented one-time-use requirement. A caller who rerandomizes the same `PresignOutput` with two different `RerandomizationArguments` (different message hashes) silently produces two `RerandomizedPresignOutput` values whose embedded nonce shares are multiplicatively related, enabling full private-key extraction via standard ECDSA nonce-reuse algebra.

---

### Finding Description

The documentation is explicit that presignatures must be consumed exactly once:

- `presign.rs` doc comment: *"it's crucial that a presignature is never reused"*
- `robust_ecdsa/README.md`: *"Each presignature is consumed **exactly once** (one-time use)"*
- `docs/ecdsa/robust_ecdsa/signing.md`: *"Never reuse a presignature, even across failed, aborted, or partially completed signing sessions"*

Despite this, the type definitions in both modules derive `Clone`:

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput { pub big_r: AffinePoint, pub k: Scalar, pub sigma: Scalar }
```

```rust
// src/ecdsa/robust_ecdsa/mod.rs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput { pub big_r: AffinePoint, pub c: Scalar, pub e: Scalar, pub alpha: Scalar, pub beta: Scalar }
```

And `rerandomize_presign` in both modules takes the presignature by shared reference, leaving the original value fully alive after the call:

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs  (identical pattern in robust_ecdsa/mod.rs)
pub fn rerandomize_presign(
    presignature: &PresignOutput,          // ← shared reference, NOT consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { … }
```

By contrast, the downstream `sign` function correctly takes `RerandomizedPresignOutput` **by value**, consuming it. The gap is that the upstream step — rerandomization — does not consume the `PresignOutput`, so nothing prevents a second call with a different `args` (different `msg_hash`).

The rerandomization formula for OT-based ECDSA is:

```
k_rerandomized = k * inv_delta
```

where `delta = HKDF(X, ε, h, R, ρ)`. If the same `PresignOutput` (same `k`) is rerandomized twice with hashes `h1` and `h2`:

```
k1 = k * inv_delta1
k2 = k * inv_delta2
=> k1 = k2 * (delta2 * inv_delta1)
```

The two nonce shares are multiplicatively related by a publicly computable scalar. Two ECDSA signatures produced from these shares expose the private key via standard nonce-reuse recovery.

The same structural issue exists in `src/ecdsa/robust_ecdsa/mod.rs` for the robust scheme's `PresignOutput` fields `(c, e, alpha, beta)`.

---

### Impact Explanation

**Critical.** If a `PresignOutput` is rerandomized twice with different message hashes — whether by an honest caller retrying after a failed session or by a malicious coordinator engineering an abort-and-retry — two ECDSA signatures are produced whose nonce shares satisfy a known linear relation. Standard ECDSA nonce-reuse algebra then recovers the full private signing key from the pair of signatures and the known relation. This matches the allowed critical impact: *"Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets."*

---

### Likelihood Explanation

**Medium.** The `Clone` derive and the by-reference API signature are the direct analogs of the "clipboard not actually cleared" behavior in the reference report: the presign output is not destroyed after use, it merely appears to be consumed because the downstream `sign` call takes `RerandomizedPresignOutput` by value. A caller who serializes presign outputs to disk for fault tolerance, or who retries a signing session after a coordinator-induced abort, will naturally reuse the same `PresignOutput`. A malicious coordinator can deliberately trigger this by aborting the first signing round after participants have already rerandomized, then initiating a second session with a different message hash against the same presign pool.

---

### Recommendation

**Short term:** Change `rerandomize_presign` in both `src/ecdsa/ot_based_ecdsa/mod.rs` and `src/ecdsa/robust_ecdsa/mod.rs` to consume `PresignOutput` by value:

```rust
pub fn rerandomize_presign(
    presignature: PresignOutput,   // consumed by value
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

This makes double-rerandomization a compile-time error for any caller holding a single `PresignOutput`.

**Long term:** Remove the `Clone` derive from `PresignOutput` in both modules. Serialization (`Serialize`/`Deserialize`) can be retained for persistence, but callers should be required to explicitly re-deserialize (and thus consciously re-introduce) a presign output rather than silently cloning it in memory.

---

### Proof of Concept

```rust
// Both calls succeed today because rerandomize_presign takes &PresignOutput
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args_h1).unwrap();
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args_h2).unwrap();

// rerand1.k = presign_out.k * inv_delta1
// rerand2.k = presign_out.k * inv_delta2
// => rerand1.k = rerand2.k * (delta2 * inv_delta1)   [publicly computable relation]

// Run sign() with rerand1 → signature (R1, s1) for h1
// Run sign() with rerand2 → signature (R2, s2) for h2
// Standard ECDSA nonce-reuse recovery on (R1,s1,h1) and (R2,s2,h2) yields the private key.
```

The `Clone` derive makes the same attack available via serialization round-trips or explicit `.clone()` calls, bypassing even a future by-value fix if `Clone` is retained. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L65-96)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
        }
        let delta = args.derive_randomness()?;
        if delta.is_zero().into() {
            return Err(ProtocolError::ZeroScalar);
        }

        // cannot be zero due to the previous check
        let inv_delta = delta.invert().unwrap();

        // delta . R
        let rerandomized_big_r = presignature.big_r * delta;

        //  (sigma + tweak * k) * delta^{-1}
        let rerandomized_sigma =
            (presignature.sigma + args.tweak.value() * presignature.k) * inv_delta;

        // k * delta^{-1}
        let rerandomized_k = presignature.k * inv_delta;

        Ok(Self {
            big_r: rerandomized_big_r.into(),
            k: rerandomized_k,
            sigma: rerandomized_sigma,
        })
    }
```

**File:** src/ecdsa/robust_ecdsa/mod.rs (L26-37)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize(skip)]
    pub big_r: AffinePoint,

    /// Our secret shares of the nonces.
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}
```

**File:** src/ecdsa/robust_ecdsa/mod.rs (L54-86)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
        }
        let delta = args.derive_randomness()?;
        if delta.is_zero().into() {
            return Err(ProtocolError::ZeroScalar);
        }

        // cannot be zero due to the previous check
        let inv_delta = delta.invert().unwrap();

        // delta * R
        let rerandomized_big_r = presignature.big_r * delta;

        // alpha * delta^{-1}
        let rerandomized_alpha = presignature.alpha * inv_delta;

        // (beta + c*tweak) * delta^{-1}
        let rerandomized_beta =
            (presignature.beta + presignature.c * args.tweak.value()) * inv_delta;

        Ok(Self {
            big_r: rerandomized_big_r.into(),
            alpha: rerandomized_alpha,
            beta: rerandomized_beta,
            e: presignature.e,
        })
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L17-19)
```rust
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-178)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.

```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L22-30)
```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L33-41)
```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: impl Into<MaxMalicious>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
```
