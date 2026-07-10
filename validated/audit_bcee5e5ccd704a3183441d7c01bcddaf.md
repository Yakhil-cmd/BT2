### Title
`PresignOutput` Not Consumed After Use Enables Presignature Reuse and Secret Key Extraction — (`src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both ECDSA variants expose a `PresignOutput` type that derives `Clone` and is accepted by `rerandomize_presign()` via shared reference (`&PresignOutput`). The presignature is therefore never cryptographically consumed after use. A library caller or malicious coordinator can call `rerandomize_presign()` multiple times with the same `PresignOutput` and different `RerandomizationArguments` (different message hashes), producing multiple valid `RerandomizedPresignOutput` values from the same nonce material. Running signing sessions with these outputs produces signatures with multiplicatively related nonces, enabling full secret key extraction — the exact attack the library's own security documentation warns against.

---

### Finding Description

The library explicitly documents that presignatures are one-time-use:

> "Each output is consumed **exactly once** (one-time use)."
> "It's **critical** that the output is then destroyed."
> "**Never reuse a presignature**, even across failed, aborted, or partially completed signing sessions."

Despite this, the API provides no enforcement. Both `PresignOutput` types derive `Clone`:

**OT-based ECDSA** (`src/ecdsa/ot_based_ecdsa/mod.rs`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }
```

**Robust ECDSA** (`src/ecdsa/robust_ecdsa/mod.rs`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }
```

And both `rerandomize_presign()` implementations accept the presignature by shared reference, never consuming it:

**OT-based** (`src/ecdsa/ot_based_ecdsa/mod.rs:66`):
```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // <-- shared reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

**Robust** (`src/ecdsa/robust_ecdsa/mod.rs:55`):
```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // <-- shared reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

Rust's ownership system would enforce one-time use if the argument were taken by value (`presignature: PresignOutput`). Instead, the caller retains full ownership of the `PresignOutput` after the call, and the `Clone` derive makes it trivial to duplicate it before passing it anywhere.

The `sign()` function correctly takes `RerandomizedPresignOutput` by value, but this protection is bypassed because the upstream `PresignOutput` is never invalidated.

---

### Impact Explanation

The security considerations in `docs/ecdsa/robust_ecdsa/signing.md` state explicitly:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks."
> "a novel split-view attack exists that can extract the secret key using as few as 2t+2 presigning participants, with as few as two signing sessions."

Because `rerandomize_presign()` takes `&PresignOutput`, a caller can produce two `RerandomizedPresignOutput` values from the same `PresignOutput` with two different message hashes `h1 ≠ h2`. The resulting signatures `(R, s1)` and `(R, s2)` share the same nonce `R` (up to the rerandomization scalar `δ`, which is deterministic from public inputs). Standard ECDSA nonce-reuse algebra then recovers the aggregate secret key `x`.

**Impact**: Critical — extraction of the aggregate private signing key.

---

### Likelihood Explanation

The attack is reachable by:

1. **An honest participant retrying a failed signing session** with the same `PresignOutput` (the most common accidental path — the library provides no guard).
2. **A malicious coordinator** who initiates two concurrent signing sessions referencing the same presignature ID but with different message hashes `h1`, `h2`. Each honest participant independently calls `rerandomize_presign()` twice on the same `PresignOutput`, producing two related signature shares. The coordinator aggregates them and recovers the key.
3. **Any library caller** who `.clone()`s a `PresignOutput` before passing it to `rerandomize_presign()`.

The `Clone` derive makes path (3) a single line of code. Path (2) requires only a malicious coordinator, which is an explicitly modeled adversary in the threshold setting.

---

### Recommendation

1. **Remove `Clone` from both `PresignOutput` types.** This prevents accidental duplication.
2. **Change `rerandomize_presign()` to consume the presignature by value:**

```rust
// Before (does not consume):
pub fn rerandomize_presign(
    presignature: &PresignOutput,
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>

// After (Rust ownership enforces one-time use):
pub fn rerandomize_presign(
    presignature: PresignOutput,
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

This mirrors the correct pattern already used by `sign()`, which takes `RerandomizedPresignOutput` by value. Applying the same pattern to `PresignOutput` closes the gap and makes the one-time-use invariant a compile-time guarantee rather than a documentation note.

---

### Proof of Concept

```rust
// Attacker (or honest-but-mistaken caller) reuses the same presignature:
let presign_out: PresignOutput = /* result of presign protocol */;

let args1 = RerandomizationArguments::new(pk, tweak, msg_hash_1, presign_out.big_r, ...);
let args2 = RerandomizationArguments::new(pk, tweak, msg_hash_2, presign_out.big_r, ...);

// Both calls succeed — presign_out is never consumed:
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args1).unwrap();
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args2).unwrap();

// Two signing sessions with the same nonce material but different messages:
let sig1 = run_sign_session(rerand1, msg_hash_1, ...);
let sig2 = run_sign_session(rerand2, msg_hash_2, ...);

// Standard ECDSA nonce-reuse recovery extracts the aggregate secret key x:
// s1 = δ^{-1}*(h1*k + r*x),  s2 = δ^{-1}*(h2*k + r*x)
// => (s1 - s2)*δ = (h1 - h2)*k  =>  k = (s1-s2)*δ / (h1-h2)
// => x = (s1*δ - h1*k) / r
```

The `Clone` derive makes the attack even simpler — a caller can `.clone()` the `PresignOutput` before passing it anywhere, retaining a copy for a second signing session. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L65-72)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
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

**File:** src/ecdsa/robust_ecdsa/mod.rs (L54-62)
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
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L150-158)
```markdown
be aware that it is vulnerable to **split-view attacks** in the robust setting when the
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.

Moreover, due to protocol modifications relative to [[DJNPO20](https://eprint.iacr.org/2020/501)] (notably signature-share
linearization), **a novel split-view attack exists that can extract the secret key using as
few as $2t + 2$ presigning participants**, with as few as two signing sessions.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-177)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.
```

**File:** src/ecdsa/ot_based_ecdsa/README.md (L12-12)
```markdown
Each output is consumed **exactly once** (one-time use).
```

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L70-72)
```markdown
It's **critical** that the output is then destroyed, so that no other
group of parties attempts to re-use that output for another phase.
In particular, the parties need some way of agreeing on which
```
