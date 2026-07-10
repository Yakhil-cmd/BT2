### Title
`PresignOutput` Not Consumed by `rerandomize_presign`, Enabling Presignature Reuse and Secret Key Extraction — (`src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both `RerandomizedPresignOutput::rerandomize_presign` implementations accept `presignature: &PresignOutput` — a shared reference — rather than consuming the value. This means the Rust type system never enforces the library's own documented invariant that each `PresignOutput` must be used exactly once. A malicious coordinator or any caller holding a `PresignOutput` can call `rerandomize_presign` multiple times with different `RerandomizationArguments`, producing multiple independent `RerandomizedPresignOutput` values from the same nonce material, and then drive separate signing sessions with each. The resulting signatures share a multiplicatively related nonce, enabling full secret-key extraction via standard ECDSA nonce-reuse attacks.

---

### Finding Description

The library's own documentation is unambiguous about the one-time-use requirement:

> *"it's crucial that a presignature is never reused"* — `src/ecdsa/robust_ecdsa/presign.rs:28-29`

> *"It's **critical** that the output is then destroyed, so that no other group of parties attempts to re-use that output for another phase."* — `docs/ecdsa/ot_based_ecdsa/orchestration.md:70-71`

> *"Never reuse a presignature, even across failed, aborted, or partially completed signing sessions."* — `docs/ecdsa/robust_ecdsa/signing.md:176`

Despite this, both `rerandomize_presign` functions take the presignature by shared reference:

**OT-based ECDSA** (`src/ecdsa/ot_based_ecdsa/mod.rs:66-67`):
```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← shared reference, NOT consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

**Robust ECDSA** (`src/ecdsa/robust_ecdsa/mod.rs:55-57`):
```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← shared reference, NOT consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

The downstream `sign` functions do consume `RerandomizedPresignOutput` by value (`src/ecdsa/ot_based_ecdsa/sign.rs:28`, `src/ecdsa/robust_ecdsa/sign.rs:39`), so the rerandomized output is correctly invalidated after one signing session. But the upstream `PresignOutput` — which contains the raw nonce shares `k`, `sigma` (OT-based) or `c`, `e`, `alpha`, `beta` (robust) — is never invalidated.

Additionally, both `PresignOutput` types derive `Clone` (`src/ecdsa/ot_based_ecdsa/mod.rs:40`, `src/ecdsa/robust_ecdsa/mod.rs:26`), making it trivial to duplicate the secret nonce material before any consumption.

The concrete attack path for a malicious coordinator:

1. Participate in the presigning protocol to obtain a `PresignOutput` containing nonce shares.
2. Call `rerandomize_presign(presign_out, args_for_msg1)` → `rerandomized1`.
3. Call `rerandomize_presign(presign_out, args_for_msg2)` → `rerandomized2` (same `presign_out`, different message/tweak).
4. Drive a signing session with `rerandomized1` for message `h1` → collect signature `(R1, s1)`.
5. Drive a signing session with `rerandomized2` for message `h2` → collect signature `(R2, s2)`.
6. Both signatures share the same underlying nonce `k`; apply standard ECDSA nonce-reuse algebra to recover the secret key.

The robust ECDSA documentation explicitly quantifies this: *"a novel split-view attack exists that can extract the secret key using as few as 2t+2 presigning participants, with as few as two signing sessions."* (`docs/ecdsa/robust_ecdsa/signing.md:157-158`).

---

### Impact Explanation

**Critical — Extraction of private signing shares / secret key material.**

Two signatures produced from the same presignature satisfy:

```
s1 = h1·k + Rx·σ   (mod q)
s2 = h2·k + Rx·σ   (mod q)
```

Subtracting: `s1 - s2 = (h1 - h2)·k`, so `k = (s1 - s2) / (h1 - h2)`. With `k` recovered, the secret key share `x` follows immediately from either equation. This is a complete, practical key extraction — not a theoretical concern.

---

### Likelihood Explanation

The attack requires only that a single party (coordinator or any participant) holds a `PresignOutput` and calls `rerandomize_presign` twice. No external assumptions, leaked keys, or cryptographic breaks are needed. The API actively permits this: the function signature accepts a shared reference, and the type derives `Clone`. Any caller who stores a `PresignOutput` (e.g., for retry logic, logging, or caching) will inadvertently create the precondition for this attack.

---

### Recommendation

**Primary fix:** Change both `rerandomize_presign` signatures to consume the `PresignOutput` by value:

```rust
pub fn rerandomize_presign(
    presignature: PresignOutput,   // consumed — enforces one-time use
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

This makes the Rust ownership system enforce the invariant at compile time, exactly as the library's documentation requires.

**Secondary fix:** Remove or gate the `Clone` derive on `PresignOutput` behind a `#[cfg(test)]` attribute, so production callers cannot trivially duplicate nonce material:

```rust
#[cfg_attr(test, derive(Clone))]
pub struct PresignOutput { ... }
```

---

### Proof of Concept

```rust
// Both OT-based and robust ECDSA are affected identically.
// Shown here for OT-based ECDSA (src/ecdsa/ot_based_ecdsa/mod.rs).

// Step 1: obtain a PresignOutput from the presigning protocol
let presign_out: PresignOutput = run_presign_protocol(...);

// Step 2: rerandomize TWICE with different messages — library allows this
let rerandomized1 = RerandomizedPresignOutput::rerandomize_presign(
    &presign_out,          // ← presign_out is NOT consumed
    &args_for_message1,
).unwrap();

let rerandomized2 = RerandomizedPresignOutput::rerandomize_presign(
    &presign_out,          // ← same presign_out reused
    &args_for_message2,
).unwrap();

// Step 3: drive two signing sessions
let sig1 = run_sign_protocol(rerandomized1, msg_hash1, ...);
let sig2 = run_sign_protocol(rerandomized2, msg_hash2, ...);

// Step 4: recover nonce k from the two signatures
// s1 - s2 = (h1 - h2) * k  =>  k = (s1.s - s2.s) * (h1 - h2)^{-1}
let k = (sig1.s - sig2.s) * (msg_hash1 - msg_hash2).invert().unwrap();

// Step 5: recover secret key x from k and one signature
// s1 = h1*k + Rx*sigma, sigma = k*x  =>  x = (s1 - h1*k) * (Rx*k)^{-1}
let r_x = x_coordinate(&sig1.big_r);
let x = (sig1.s - msg_hash1 * k) * (r_x * k).invert().unwrap();
// x is now the reconstructed secret key
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L65-67)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
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

**File:** src/ecdsa/robust_ecdsa/mod.rs (L54-57)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L22-29)
```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L23-29)
```rust
/// The presignature protocol.
///
/// This is the first phase of performing a signature, in which we perform
/// all the work we can do without yet knowing the message to be signed.
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```
