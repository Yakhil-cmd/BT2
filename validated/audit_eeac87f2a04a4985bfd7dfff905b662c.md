### Title
Presignature Replay via Non-Consuming `rerandomize_presign` API Enables Secret Key Extraction — (`src/ecdsa/robust_ecdsa/mod.rs`, `src/ecdsa/ot_based_ecdsa/mod.rs`)

---

### Summary

Both ECDSA schemes expose a `PresignOutput` type that is `Clone`-able and whose rerandomization entry point (`rerandomize_presign`) accepts the presignature **by shared reference** rather than by value. This means a single `PresignOutput` can be rerandomized and consumed in multiple independent signing sessions. A malicious coordinator can exploit this to obtain two valid signatures that share the same underlying nonce, enabling full secret-key extraction via standard ECDSA nonce-reuse algebra.

---

### Finding Description

`PresignOutput` in both schemes derives `Clone` and `Serialize`/`Deserialize`:

```rust
// src/ecdsa/robust_ecdsa/mod.rs  (PresignOutput – not shown in full, but used below)
// src/ecdsa/ot_based_ecdsa/mod.rs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput { … }
```

The rerandomization function takes the presignature **by shared reference**:

```rust
// src/ecdsa/robust_ecdsa/mod.rs  lines 55-86
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { … }
``` [1](#0-0) 

The same pattern exists in the OT-based scheme:

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs  lines 65-96
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { … }
``` [2](#0-1) 

The downstream `sign()` function does consume `RerandomizedPresignOutput` by value, but this only prevents reuse of the *rerandomized* wrapper — the raw `PresignOutput` (which holds the actual nonce material) is never consumed and remains available for a second rerandomization call. [3](#0-2) 

The `RerandomizationArguments` struct, which binds the presignature to a specific `(h, ε, entropy, participants)` context, is also accepted by reference and is freely reusable: [4](#0-3) 

The library's own security documentation acknowledges the consequence:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks." [5](#0-4) 

Despite this warning, the library provides **no programmatic enforcement** of single-use. The `Clone` bound on `PresignOutput` and the by-reference API of `rerandomize_presign` together make it trivially easy — and type-safe from Rust's perspective — to rerandomize the same presignature twice.

---

### Impact Explanation

**Critical — Extraction of private signing shares / aggregate secret key.**

Given two signatures `(R₁, s₁)` and `(R₂, s₂)` produced from the same presignature nonce `k` (even after different rerandomizations with scalars `δ₁` and `δ₂`), the nonces are multiplicatively related: `R₁ = δ₁·R₀`, `R₂ = δ₂·R₀`. Both `δ` values are deterministic and public (derived via HKDF from public inputs). An attacker who controls the coordinator and observes both signatures can recover the master secret key `x` using standard two-equation ECDSA nonce-reuse algebra. This is a complete, permanent compromise of the key material generated during DKG.

---

### Likelihood Explanation

A malicious coordinator is an explicitly in-scope attacker. The coordinator controls which `RerandomizationArguments` (message hash, tweak, entropy) are presented to each participant. Honest participants have no way to detect that the `PresignOutput` they hold has already been used in a prior session — the library exposes no session identifier, use-counter, or consumed flag. The coordinator simply initiates two signing sessions back-to-back with the same presignature set and different `(h, ε)` pairs. Both sessions succeed from the participants' perspective, and the coordinator collects two valid signatures sufficient for key extraction.

---

### Recommendation

1. **Remove `Clone` from `PresignOutput`** in both schemes. This prevents callers from silently duplicating nonce material.
2. **Change `rerandomize_presign` to consume `PresignOutput` by value** (`presignature: PresignOutput`). Rust's move semantics then statically guarantee single-use at the call site.
3. If serialization/deserialization of `PresignOutput` must be retained for persistence, document that deserializing and reusing a stored presignature is a critical security violation, and consider wrapping it in a type that zeroizes on drop and cannot be cloned.

---

### Proof of Concept

```
1. Coordinator runs presign with participants P₁…Pₙ.
   Each Pᵢ holds PresignOutput { big_r: R₀, alpha_i, beta_i, c_i, e_i }.

2. Coordinator constructs RerandomizationArguments args1 = (pk, ε₁, h₁, R₀, P, ρ₁).
   Each Pᵢ calls:
       let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args1);
       // presign_out is NOT consumed — still valid
   Signing session 1 completes → signature (R₁, s₁).

3. Coordinator constructs RerandomizationArguments args2 = (pk, ε₂, h₂, R₀, P, ρ₂).
   Each Pᵢ calls:
       let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args2);
       // same presign_out reused — library accepts this without error
   Signing session 2 completes → signature (R₂, s₂).

4. Coordinator knows δ₁ = HKDF(args1) and δ₂ = HKDF(args2) (both public).
   R₁ = δ₁·R₀,  R₂ = δ₂·R₀  →  nonces are related by known scalar δ₁/δ₂.
   Two ECDSA equations with related nonces → solve for master secret key x.
```

### Citations

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

**File:** src/ecdsa/mod.rs (L94-103)
```rust
pub struct RerandomizationArguments {
    // Preferable (but non-binding) the master public key
    pub pk: AffinePoint,
    pub tweak: Tweak,
    pub msg_hash: [u8; 32],
    pub big_r: AffinePoint,
    pub participants: ParticipantList,
    /// Fresh, Unpredictable, and Public source of entropy
    pub entropy: [u8; 32],
}
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L151-154)
```markdown
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.
```
