### Title
Presignature Granted Unlimited Signing Capability via `Clone`-able `PresignOutput` and Non-Consuming `rerandomize_presign` API — (File: `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

### Summary

Both OT-based and Robust ECDSA `PresignOutput` structs derive `Clone`, and `rerandomize_presign` accepts `presignature: &PresignOutput` (a shared reference) rather than consuming the presignature by value. This API design grants an "unlimited signing allowance" to a presignature — it can be rerandomized and submitted to the signing protocol an arbitrary number of times. A malicious coordinator can exploit this by aborting a signing session after collecting signature shares, then initiating a second session against the same presignature, collecting a second set of shares, and using both sets to recover the private key through a nonce-reuse attack. The security documentation explicitly forbids presignature reuse but the library enforces no such constraint at the API level.

### Finding Description

**Root cause — OT-based ECDSA:**

`PresignOutput` in `src/ecdsa/ot_based_ecdsa/mod.rs` derives `Clone`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,
    pub sigma: Scalar,
}
```

`rerandomize_presign` takes a shared reference, leaving the original intact:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← shared ref, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { … }
```

`RerandomizedPresignOutput` also derives `Clone`, so even the rerandomized form can be duplicated before being passed to `sign()`.

**Root cause — Robust ECDSA:**

Identical pattern in `src/ecdsa/robust_ecdsa/mod.rs`:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← shared ref, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { … }
```

`RerandomizedPresignOutput` also derives `Clone`.

**Documented constraint that the API fails to enforce:**

`docs/ecdsa/robust_ecdsa/signing.md` lines 176–177 state:

> **Never reuse a presignature**, even across failed, aborted, or partially completed signing sessions.

The library provides no mechanism to mark a presignature as consumed. Because `PresignOutput` is `Clone`-able and `rerandomize_presign` borrows it, a caller — or a malicious coordinator who controls the session lifecycle — can trivially trigger two independent signing sessions against the same nonce material.

**Concrete exploit path (malicious coordinator):**

1. Coordinator initiates signing session 1 with `(h₁, tweak₁, entropy₁)`.
2. Honest participants rerandomize their presignature shares with `δ₁ = HKDF(entropy₁, …)` and compute `s_i1`; they send `s_i1` to the coordinator.
3. Coordinator collects all `s_i1` values (enough to reconstruct `s₁`) but **aborts** — never broadcasts the final signature. Participants cannot tell whether the presignature was consumed.
4. Coordinator initiates signing session 2 with `(h₂, tweak₂, entropy₂)` against the **same presignature**.
5. Participants, having no API-level guard preventing reuse, rerandomize the same presignature with `δ₂ = HKDF(entropy₂, …)`