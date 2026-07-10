### Title
`PresignOutput` Lacks One-Time-Use Enforcement, Enabling Presignature Reuse and Private Key Extraction — (File: `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both ECDSA variants document that each `PresignOutput` must be consumed **exactly once**, but neither enforces this at the type or API level. `PresignOutput` derives `Clone` and `rerandomize_presign` accepts `&PresignOutput` (a shared reference, not an owned value), so the presignature is never consumed. A malicious coordinator can call `rerandomize_presign` multiple times on the same `PresignOutput` with different `(msg_hash, tweak, entropy)` arguments, run two signing sessions against the same underlying nonce, and recover the aggregate private key via standard ECDSA nonce-reuse algebra.

---

### Finding Description

The README for both ECDSA modules explicitly states the one-time-use requirement:

> "Each output is consumed **exactly once** (one-time use)."
> "Never reuse a presignature, even across failed, aborted, or partially completed signing sessions."

However, the type definitions contradict this intent:

**OT-based ECDSA** (`src/ecdsa/ot_based_ecdsa/mod.rs`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }
``` [1](#0-0) 

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // shared reference — not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { ... }
``` [2](#0-1) 

**Robust ECDSA** (`src/ecdsa/robust_ecdsa/mod.rs`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }
``` [3](#0-2) 

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // shared reference — not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { ... }
``` [4](#0-3) 

Because `PresignOutput` is `Clone` and `rerandomize_presign` takes `&PresignOutput`, nothing in the library prevents a caller from invoking `rerandomize_presign` twice on the same presignature with different `RerandomizationArguments`. The library enforces other split-view constraints (e.g., `participants.len() == 2*max_malicious+1`, `msg_hash != 0`) but has no analogous guard against presignature reuse. [5](#0-4) 

The security documentation explicitly names the consequence:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks." [6](#0-5) 

---

### Impact Explanation

**Critical — Extraction/reconstruction of private signing shares.**

Two signatures produced from the same underlying nonce `k` (even after distinct rerandomizations `δ1`, `δ2`) satisfy:

```
R1 = δ1·R,  s1 = (k/δ1)·h1 + (σ + ε1·k)/δ1 · r1
R2 = δ2·R,  s2 = (k/δ2)·h2 + (σ + ε2·k)/δ2 · r2
```

Because `R1` and `R2` are scalar multiples of the same base point `R`, the nonces are multiplicatively related. Standard ECDSA nonce-reuse linear algebra over the two equations yields the aggregate secret `x` (the threshold private key). This is a complete key compromise.

---

### Likelihood Explanation

**High.** The malicious coordinator is an explicitly modeled adversary in this library. The coordinator already controls `RerandomizationArguments` (choosing `msg_hash`, `tweak`, `entropy`, and `participants`). Nothing prevents the coordinator from:

1. Receiving a completed `PresignOutput` from the presigning phase.
2. Calling `rerandomize_presign(presig, args1)` → `RerandomizedPresignOutput1`.
3. Calling `rerandomize_presign(presig, args2)` with a different `msg_hash` or `tweak` → `RerandomizedPresignOutput2`.
4. Running two signing sessions, collecting both signatures.
5. Solving for the private key.

No special precondition (leaked key, external compromise, cryptographic break) is required. The attack is purely a consequence of the missing one-time-use enforcement in the library API.

---

### Recommendation

Change `rerandomize_presign` to consume the `PresignOutput` by value rather than by reference, so Rust's ownership system enforces the one-time-use invariant at compile time:

```rust
// Before (both variants):
pub fn rerandomize_presign(
    presignature: &PresignOutput,
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>

// After:
pub fn rerandomize_presign(
    presignature: PresignOutput,   // consumed — cannot be reused
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

Additionally, remove the `Clone` derive from `PresignOutput` in both modules to prevent callers from cloning the presignature before passing it in, which would circumvent the ownership-based protection.

---

### Proof of Concept

```rust
// Malicious coordinator scenario (robust ECDSA):
let presign_output: PresignOutput = /* result of presigning phase */;

// First rerandomization — different message
let args1 = RerandomizationArguments::new(pk, tweak1, msg_hash1, big_r, participants.clone(), entropy1);
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presign_output, &args1).unwrap();

// Second rerandomization — same presignature, different message (REUSE)
let args2 = RerandomizationArguments::new(pk, tweak2, msg_hash2, big_r, participants.clone(), entropy2);
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presign_output, &args2).unwrap();

// Run two signing sessions → two signatures with multiplicatively related nonces
// → recover private key via standard ECDSA nonce-reuse algebra
```

`PresignOutput` is `Clone`, so even if the API were changed to take ownership, a caller could still write `rerandomize_presign(presign_output.clone(), &args1)` followed by `rerandomize_presign(presign_output, &args2)`. Both `Clone` removal and ownership-by-value are required together to close the gap. [1](#0-0) [3](#0-2)

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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L74-79)
```rust
    // To prevent split-view attacks documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during presigning must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L151-154)
```markdown
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.
```
