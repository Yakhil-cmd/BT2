### Title
Presignature Nonce Reuse via Non-Consuming `rerandomize_presign` API Enables Private Key Recovery - (File: `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

### Summary
Both the OT-based and Robust ECDSA presignature types (`PresignOutput`) derive `Clone` and their rerandomization entry points accept a shared reference (`&PresignOutput`), meaning the underlying nonce material is never consumed or invalidated after use. A malicious coordinator can trigger honest parties to rerandomize and sign with the same presignature for two different messages, producing two ECDSA signatures with algebraically related nonces from which the aggregate private key can be recovered.

### Finding Description

`PresignOutput` in both ECDSA variants is defined as a cloneable, serializable struct:

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,
    pub sigma: Scalar,
}
``` [1](#0-0) 

The rerandomization function takes the presignature by shared reference, not by value:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // <-- reference, not ownership
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {
``` [2](#0-1) 

Because `rerandomize_presign` takes `&PresignOutput` rather than consuming it, the caller's `PresignOutput` value is never invalidated. Combined with `Clone`, there is no API-level mechanism preventing a party from calling `rerandomize_presign` on the same `PresignOutput` for two different messages.

The Robust ECDSA variant has the same structural issue: [3](#0-2) 

The library's own documentation acknowledges the danger but relies entirely on caller discipline:

> "It's **critical** that the output is then destroyed, so that no other group of parties attempts to re-use that output for another phase." [4](#0-3) 

> "Never reuse a presignature, even across failed, aborted, or partially completed signing sessions." [5](#0-4) 

**Attack path (malicious coordinator):**

1. Honest parties complete presigning; each holds their local `PresignOutput` share `(R, k_i, sigma_i)`.
2. Coordinator initiates signing session 1 for message `m1`. Each honest party calls `rerandomize_presign(&presign_output, args_m1)` and sends their signature share `s_i^(1)`. Coordinator assembles signature `(R1, s1)`.
3. Coordinator initiates signing session 2 for message `m2`, referencing the **same presignature context**. Because `PresignOutput` was not consumed, each honest party still holds it and calls `rerandomize_presign(&presign_output, args_m2)`, sending `s_i^(2)`. Coordinator assembles `(R2, s2)`.
4. Coordinator now holds two signatures whose nonces satisfy `k1 = k · δ1^{-1}` and `k2 = k · δ2^{-1}` where `δ1, δ2` are both known (derived from public HKDF inputs). The relationship `k1 · δ1 = k2 · δ2` is known, enabling private key extraction via standard related-nonce ECDSA algebra.

The Robust ECDSA security section confirms this directly:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks." [6](#0-5) 

### Impact Explanation

A malicious coordinator who can initiate two signing sessions referencing the same presignature recovers the aggregate ECDSA private key. This is a **Critical** impact: extraction of aggregate secret material (the private signing key) via nonce reuse. All future and past signatures under that key are compromised.

### Likelihood Explanation

The coordinator role is explicitly part of the protocol model and is reachable without any privileged key material. The library provides no API-level guard (no ownership transfer, no use-flag, no session binding) to prevent a coordinator from triggering two signing rounds against the same presignature. Any deployment where the coordinator is not fully trusted and presignature lifetime is not externally managed is vulnerable.

### Recommendation

Change `rerandomize_presign` to consume the `PresignOutput` by value:

```rust
pub fn rerandomize_presign(
    presignature: PresignOutput,   // consume by value
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

This makes it a compile-time error to call `rerandomize_presign` twice on the same `PresignOutput`. Additionally, remove the `Clone` derive from `PresignOutput` (or at minimum document it as `#[doc(hidden)]` with a strong warning), so that callers cannot trivially clone the value before passing it in to circumvent the ownership check.

### Proof of Concept

Given two signatures produced from the same presignature nonce `k` with rerandomization scalars `δ1 = HKDF(X, ε, h1, R, ρ)` and `δ2 = HKDF(X, ε, h2, R, ρ)`:

```
k1 = k · δ1^{-1},  R1 = δ1 · R  →  r1 = R1.x
k2 = k · δ2^{-1},  R2 = δ2 · R  →  r2 = R2.x

s1 = k1 · (h1 + r1 · x)   →   s1 · δ1 = k · (h1 + r1 · x)
s2 = k2 · (h2 + r2 · x)   →   s2 · δ2 = k · (h2 + r2 · x)

Dividing and solving for x (all quantities on the right are public):

x = (s2·δ2·h1 − s1·δ1·h2) / (s1·δ1·r2 − s2·δ2·r1)
```

All inputs (`s1`, `s2`, `δ1`, `δ2`, `h1`, `h2`, `r1`, `r2`) are known to the coordinator after collecting both signing sessions, yielding a closed-form recovery of the private key `x`.

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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L66-70)
```rust
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

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L70-73)
```markdown
It's **critical** that the output is then destroyed, so that no other
group of parties attempts to re-use that output for another phase.
In particular, the parties need some way of agreeing on which
outputs have been created and used.
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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-178)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.

```
