### Title
`PresignOutput` Not Consumed by `rerandomize_presign`, Enabling Presignature Reuse and Private Key Extraction — (`src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both the OT-based and robust ECDSA schemes expose `RerandomizedPresignOutput::rerandomize_presign` accepting `presignature: &PresignOutput` — a shared reference — rather than consuming the value by ownership. Combined with `PresignOutput` deriving `Clone`, `Serialize`, and `Deserialize`, the library provides no type-level enforcement of the one-time-use invariant that the protocol's security critically depends on. A caller (including a malicious coordinator) can rerandomize the same `PresignOutput` for two different messages, producing two signatures with multiplicatively related nonces, from which the aggregate secret key can be recovered by standard ECDSA nonce-reuse algebra.

---

### Finding Description

The library's own documentation states the invariant unambiguously:

> "Each output is consumed **exactly once** (one-time use)."
> "it's crucial that a presignature is never reused."
> "**Never reuse a presignature**, even across failed, aborted, or partially completed signing sessions."

Despite this, the API does not enforce it. In both schemes, `rerandomize_presign` borrows the presignature:

**OT-based ECDSA** (`src/ecdsa/ot_based_ecdsa/mod.rs`):
```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← shared reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

**Robust ECDSA** (`src/ecdsa/robust_ecdsa/mod.rs`):
```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← shared reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

Additionally, `PresignOutput` derives `Clone`, `Serialize`, and `Deserialize` in both modules, making it trivially copyable and persistable across calls.

The downstream `sign()` functions do consume `RerandomizedPresignOutput` by value, but this is too late: the one-time-use invariant is broken at the rerandomization step, before signing.

The `PresignArguments` struct in OT-based ECDSA also derives `Clone`, meaning the `TripleShare` values it contains can be cloned and fed into multiple presigning sessions, compounding the issue upstream.

---

### Impact Explanation

**Critical — private key extraction via multiplicatively related nonces.**

When `rerandomize_presign` is called twice on the same `PresignOutput` with different `RerandomizationArguments` (different messages `h1`, `h2` or tweaks `ε1`, `ε2`), the two resulting `RerandomizedPresignOutput` values share the same underlying nonce scalar `k`, scaled by different deltas:

- Call 1: `k_rerandomized_1 = k · δ₁⁻¹`, `R₁ = δ₁ · R`
- Call 2: `k_rerandomized_2 = k · δ₂⁻¹`, `R₂ = δ₂ · R`

The two nonces are multiplicatively related: `k₁ / k₂ = δ₂ / δ₁`. The library's own security documentation confirms the consequence:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and **the secret key can be recovered using standard ECDSA nonce-reuse attacks**."

This maps directly to the allowed Critical impact: **extraction of private signing shares / aggregate secret material**.

---

### Likelihood Explanation

**High.** The vulnerability requires no cryptographic break, no external compromise, and no special privilege beyond being a library caller. Any participant who stores a `PresignOutput` (which is `Clone + Serialize + Deserialize`) can trivially reuse it. A malicious coordinator can orchestrate two signing sessions against the same presignature with different messages. The API actively invites this misuse by accepting a reference rather than consuming the value. The only protection is a documentation warning, which is insufficient for a security-critical invariant.

---

### Recommendation

Enforce one-time use at the type level by consuming `PresignOutput` by value in `rerandomize_presign`:

```rust
pub fn rerandomize_presign(
    presignature: PresignOutput,   // consume by value
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

Additionally:
- Remove the `Clone` derive from `PresignOutput` in both modules to prevent callers from circumventing the ownership-based protection.
- Remove `Clone` from `PresignArguments` in `ot_based_ecdsa` to prevent triple reuse upstream.
- Consider removing `Serialize`/`Deserialize` from `PresignOutput`, or at minimum documenting that deserialization and re-use of a previously serialized presignature violates the security model.

---

### Proof of Concept

**Setup**: Two participants run presigning and each obtains a `PresignOutput` with nonce share `k_i` and commitment `R`.

**Attack** (single participant, malicious coordinator):

1. Coordinator runs presigning protocol; each participant `i` receives `PresignOutput { big_r: R, k: k_i, sigma: sigma_i }`.
2. Coordinator calls `rerandomize_presign(&presign_output, &args_for_msg1)` → `rerandomized_1` (nonce `k_i / δ₁`).
3. Coordinator calls `rerandomize_presign(&presign_output, &args_for_msg2)` → `rerandomized_2` (nonce `k_i / δ₂`). The `PresignOutput` is still valid because it was never consumed.
4. Coordinator runs two signing sessions: one with `rerandomized_1` and message `h₁`, one with `rerandomized_2` and message `h₂`.
5. The two resulting ECDSA signatures `(R₁, s₁)` and `(R₂, s₂)` satisfy `k₁ = δ₂/δ₁ · k₂`. Since `δ₁` and `δ₂` are HKDF-derived from known public inputs `(R, h, ε, participants)`, the ratio `δ₂/δ₁` is computable by the attacker.
6. Standard multiplicative nonce-reuse recovery yields the aggregate secret key `x`.

The same attack applies to the robust ECDSA scheme identically, as confirmed by `docs/ecdsa/robust_ecdsa/signing.md:151-154`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L23-34)
```rust
#[derive(Debug, Clone)]
pub struct PresignArguments {
    /// The first triple's public information, and our share.
    pub triple0: (TripleShare, TriplePub),
    /// Ditto, for the second triple.
    pub triple1: (TripleShare, TriplePub),
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type `KeygenOutput<Secp256K1Sha256>` from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub threshold: ReconstructionLowerBound,
}
```

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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L65-70)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
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

**File:** src/ecdsa/robust_ecdsa/mod.rs (L54-59)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L151-154)
```markdown
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-177)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.
```
