### Title
Presignature Can Be Rerandomized Unlimited Times, Enabling Nonce Reuse and Secret Key Extraction — (`src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both the OT-based and Robust ECDSA implementations expose `rerandomize_presign` as a function that takes the `PresignOutput` by shared reference (`&PresignOutput`) rather than consuming it. Because `PresignOutput` also derives `Clone`, the library provides no type-level or runtime enforcement of the critical single-use constraint on presignatures. A malicious coordinator can instruct honest participants to rerandomize and sign with the same presignature an unlimited number of times across different `(msg_hash, tweak)` pairs, producing signatures whose nonces are algebraically related. Standard ECDSA nonce-reuse analysis then recovers the aggregate secret key.

---

### Finding Description

`PresignOutput` in both ECDSA variants is defined as:

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,
    pub sigma: Scalar,
}
``` [1](#0-0) 

```rust
// src/ecdsa/robust_ecdsa/mod.rs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub c: Scalar, pub e: Scalar, pub alpha: Scalar, pub beta: Scalar,
}
``` [2](#0-1) 

The rerandomization entry point for both variants takes the presignature by **shared reference**:

```rust
// OT-based (src/ecdsa/ot_based_ecdsa/mod.rs)
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← shared reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { … }
``` [3](#0-2) 

```rust
// Robust (src/ecdsa/robust_ecdsa/mod.rs)
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← shared reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { … }
``` [4](#0-3) 

By contrast, the downstream `sign()` functions **do** consume the `RerandomizedPresignOutput` by value, so each individual signing call is single-use. However, because `rerandomize_presign` never consumes the underlying `PresignOutput`, a caller can invoke it repeatedly on the same presignature with different `RerandomizationArguments` (different `msg_hash`, `tweak`, `entropy`), producing an unlimited number of distinct `RerandomizedPresignOutput` values — each of which is valid input to a fresh signing session.

The security documentation explicitly identifies this as catastrophic:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks." [5](#0-4) 

The presigning comment itself acknowledges the constraint but does not enforce it:

> "it's crucial that a presignature is never reused" [6](#0-5) 

---

### Impact Explanation

The rerandomization for session $i$ with factor $\delta_i$ produces:

- $R_i = \delta_i \cdot R$, $k_i' = k \cdot \delta_i^{-1}$

Two sessions sharing the same underlying nonce $k$ yield ECDSA signatures:

$$s_1 = \frac{h_1 + x \cdot r_1}{k_1'} = \frac{(h_1 + x \cdot r_1)\,\delta_1}{k}, \quad s_2 = \frac{(h_2 + x \cdot r_2)\,\delta_2}{k}$$

Since $\delta_1, \delta_2, r_1, r_2, h_1, h_2$ are all known to the coordinator, two equations in one unknown $x$ (the aggregate secret key) are immediately solvable. This is a **Critical** impact: full extraction of the aggregate private signing key.

---

### Likelihood Explanation

The attack requires only a **malicious coordinator**, which is an explicitly documented threat actor for this library. The coordinator controls which `RerandomizationArguments` are passed to each participant. Because `rerandomize_presign` does not consume the `PresignOutput`, honest participants have no library-enforced mechanism to detect that they are being asked to reuse a presignature. The coordinator simply initiates two signing sessions referencing the same presignature material with different `(msg_hash, tweak)` pairs. No cryptographic break, no leaked keys, and no external dependency is required.

---

### Recommendation

Change `rerandomize_presign` to **consume** the `PresignOutput` by value in both variants:

```rust
pub fn rerandomize_presign(
    presignature: PresignOutput,   // ← take ownership, enforcing single-use
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { … }
```

This makes presignature reuse a **compile-time error** in Rust: once `rerandomize_presign` is called, the `PresignOutput` is moved and cannot be used again. Additionally, remove the `Clone` derive from `PresignOutput` in both `src/ecdsa/ot_based_ecdsa/mod.rs` and `src/ecdsa/robust_ecdsa/mod.rs` to prevent callers from trivially circumventing the ownership discipline by cloning before the call.

---

### Proof of Concept

```rust
// Attacker-controlled coordinator scenario (OT-based ECDSA)
let presign_out: PresignOutput = /* result of presign protocol */;

// Session 1: sign message h1 with tweak ε1
let args1 = RerandomizationArguments::new(pk, tweak1, h1_bytes, presign_out.big_r, participants.clone(), entropy1);
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args1).unwrap();
// presign_out is NOT consumed — still fully usable

// Session 2: sign message h2 with tweak ε2 using the SAME presignature
let args2 = RerandomizationArguments::new(pk, tweak2, h2_bytes, presign_out.big_r, participants.clone(), entropy2);
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args2).unwrap();

// Both signing sessions complete successfully.
// Coordinator now holds (R1,s1) and (R2,s2) derived from the same nonce k.
// Since δ1, δ2 are deterministic from public args, solve:
//   s1·k = (h1 + x·r1)·δ1
//   s2·k = (h2 + x·r2)·δ2
// → extract aggregate secret key x.
``` [3](#0-2) [4](#0-3)

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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L17-19)
```rust
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```
