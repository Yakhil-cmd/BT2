### Title
`PresignOutput` Reuse Enabled by Non-Consuming `rerandomize_presign` API — (`File: src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both `ot_based_ecdsa::RerandomizedPresignOutput::rerandomize_presign` and `robust_ecdsa::RerandomizedPresignOutput::rerandomize_presign` accept the presignature by shared reference (`&PresignOutput`) rather than by value. This means the library never enforces the documented one-time-use invariant at the type level. A caller — including a malicious coordinator or any party that holds a `PresignOutput` — can call `rerandomize_presign` multiple times on the same `PresignOutput` with different `RerandomizationArguments`, producing multiple signing sessions that share the same underlying nonce material. Two resulting ECDSA signatures with multiplicatively related nonces are sufficient to extract the aggregate private key.

---

### Finding Description

The library's own documentation is unambiguous:

> "Each output is consumed **exactly once** (one-time use)."
> "it's crucial that a presignature is never reused." [1](#0-0) [2](#0-1) 

Despite this, both `rerandomize_presign` implementations accept the presignature as a **shared reference**, not by value:

```rust
// ot_based_ecdsa
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // <-- shared reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
``` [3](#0-2) 

```rust
// robust_ecdsa
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // <-- shared reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
``` [4](#0-3) 

Both `PresignOutput` types also derive `Clone`, making it trivial to store and reuse copies: [5](#0-4) [6](#0-5) 

Because the caller retains ownership after `rerandomize_presign` returns, nothing prevents calling it again with a different `RerandomizationArguments` (different `msg_hash`, `tweak`, or `entropy`). Each call produces a distinct `RerandomizedPresignOutput` with a different `delta`, but all derived from the same secret nonce `k`.

For OT-based ECDSA, the rerandomization produces:
- Session 1: `k₁ = k · δ₁⁻¹`, `R₁ = δ₁ · R`
- Session 2: `k₂ = k · δ₂⁻¹`, `R₂ = δ₂ · R`

The nonces satisfy `k₁ = k₂ · (δ₂/δ₁)` — a multiplicative relationship. The robust ECDSA security documentation explicitly names this as the attack vector:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks." [7](#0-6) 

The orchestration documentation further confirms the criticality:

> "It's **critical** that the output is then destroyed, so that no other group of parties attempts to re-use that output for another phase." [8](#0-7) 

---

### Impact Explanation

Two signatures produced from the same `PresignOutput` with different `RerandomizationArguments` yield two equations in the unknown private key `x` and the shared nonce `k`. Standard ECDSA nonce-reuse algebra recovers `x` (the aggregate secret key) from these two equations. This constitutes **extraction of the aggregate private signing key** — the highest-severity outcome in threshold signature systems.

Impact: **Critical** — extraction/reconstruction of aggregate secret material (private key).

---

### Likelihood Explanation

The entry path requires only that a party holding a `PresignOutput` calls `rerandomize_presign` twice. This is:

- **Reachable by a malicious coordinator**: the coordinator orchestrates signing sessions and naturally holds presignatures. Nothing in the API prevents it from initiating two signing sessions with the same presignature for different messages.
- **Reachable by any participant**: `PresignOutput` is a public struct with public fields; any participant who receives their share can call `rerandomize_presign` locally.
- **Reachable accidentally**: the `&PresignOutput` API signature gives no indication that the value must be destroyed after use; a well-intentioned integrator can easily reuse it.

The `Clone` derive compounds the risk by making it trivial to store a copy before passing to any consuming context.

---

### Recommendation

Change both `rerandomize_presign` functions to consume the `PresignOutput` by value, enforcing single-use at the type level:

```rust
// ot_based_ecdsa
pub fn rerandomize_presign(
    presignature: PresignOutput,   // consume by value
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>

// robust_ecdsa
pub fn rerandomize_presign(
    presignature: PresignOutput,   // consume by value
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

Additionally, remove the `Clone` derive from both `PresignOutput` types to prevent callers from circumventing the ownership-based protection by cloning before passing. [9](#0-8) [10](#0-9) 

---

### Proof of Concept

```rust
// Both ot_based_ecdsa and robust_ecdsa are affected identically.
// Shown here for robust_ecdsa.

let presign_output: PresignOutput = /* result of presign protocol */;

// First signing session — legitimate
let args1 = RerandomizationArguments::new(pk, tweak1, msg_hash1, presign_output.big_r, participants.clone(), entropy1);
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presign_output, &args1).unwrap();
// ... run sign protocol with rerand1, obtain signature (R1, s1)

// Second signing session — REUSE of the same presign_output
let args2 = RerandomizationArguments::new(pk, tweak2, msg_hash2, presign_output.big_r, participants.clone(), entropy2);
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presign_output, &args2).unwrap();
// ... run sign protocol with rerand2, obtain signature (R2, s2)

// Now (R1, s1) and (R2, s2) have multiplicatively related nonces.
// Standard ECDSA nonce-reuse algebra recovers the aggregate private key x.
```

`rerandomize_presign` accepts `&PresignOutput` at both call sites without error, and `presign_output` remains valid and reusable throughout. [11](#0-10) [12](#0-11)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/README.md (L12-12)
```markdown
Each output is consumed **exactly once** (one-time use).
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L17-19)
```rust
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
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

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L70-73)
```markdown
It's **critical** that the output is then destroyed, so that no other
group of parties attempts to re-use that output for another phase.
In particular, the parties need some way of agreeing on which
outputs have been created and used.
```
