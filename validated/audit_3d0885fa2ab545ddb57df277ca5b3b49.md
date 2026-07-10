### Title
No API-Level Enforcement of Presignature Single-Use Allows Malicious Coordinator to Recover Secret Key - (`src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

### Summary

Both the OT-based and Robust ECDSA schemes require that each `PresignOutput` is consumed **exactly once**. However, the library provides no mechanism to enforce this invariant: `rerandomize_presign` accepts `&PresignOutput` (a shared reference, not consuming the value), and `PresignOutput` derives `Clone + Serialize + Deserialize`. A malicious coordinator can exploit this by initiating two signing sessions with different messages against the same presignature, obtaining two sets of signature shares from honest participants who have no way to detect the reuse, and then recovering the aggregate secret key via standard ECDSA nonce-reuse algebra.

### Finding Description

Both `PresignOutput` types are defined with `Clone`, `Serialize`, and `Deserialize`:

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput { pub big_r: AffinePoint, pub k: Scalar, pub sigma: Scalar }
``` [1](#0-0) 

```rust
// src/ecdsa/robust_ecdsa/mod.rs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput { pub big_r: AffinePoint, pub c: Scalar, pub e: Scalar, pub alpha: Scalar, pub beta: Scalar }
``` [2](#0-1) 

The rerandomization function takes the presignature **by shared reference**, not by value:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← shared reference; not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
``` [3](#0-2) [4](#0-3) 

The library's own documentation explicitly states the one-time-use requirement:

> "Each output is consumed **exactly once** (one-time use)."
> "It's **critical** that the output is then destroyed."
> "**Never reuse a presignature**, even across failed, aborted, or partially completed signing sessions." [5](#0-4) [6](#0-5) [7](#0-6) 

Despite this, the library provides **no API-level enforcement**:
- `rerandomize_presign` does not consume the `PresignOutput`
- `PresignOutput` derives `Clone`, so it can be duplicated before use
- `PresignOutput` derives `Serialize`/`Deserialize`, so it can be persisted and reloaded
- There is no usage flag, no consumption-by-value, and no invalidation mechanism

The attack path for a malicious coordinator:

1. Participants complete presigning; each holds their local `PresignOutput` share `(R, α_i, β_i, c_i, e_i)`.
2. Coordinator initiates **Session 1** with message hash `h₁` and entropy `ρ₁`. Each participant calls `rerandomize_presign(&presign_out, &args1)` and sends their signature share `s_i` to the coordinator.
3. Coordinator **aborts** Session 1 after collecting all shares (or simply records them without completing).
4. Coordinator initiates **Session 2** with a different message hash `h₂` (or different tweak `ε₂`) and entropy `ρ₂`. Participants have no mechanism to detect that this is the same presignature — `presign_out` was never consumed or invalidated — so they call `rerandomize_presign(&presign_out, &args2)` again and send new shares.
5. The coordinator now holds two complete sets of signature shares derived from the same underlying nonce `k`. Using the two resulting signatures `(R, s₁)` and `(R', s₂)` (where `R' = δ₂·R` and `R = δ₁·R`), the coordinator can apply standard ECDSA nonce-reuse algebra to recover the secret key `x`.

The security documentation confirms this consequence explicitly:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks." [8](#0-7) 

### Impact Explanation

A malicious coordinator recovers the aggregate ECDSA secret key by collecting two sets of honest participants' signature shares derived from the same presignature nonce. This constitutes **extraction of the aggregate secret material** — the highest-severity impact in the allowed scope. All future and past signatures under that key are compromised.

### Likelihood Explanation

The coordinator role is reachable without privileged assumptions (it is a designated participant in every signing session). A malicious coordinator can trivially trigger this by aborting a signing session after collecting shares and then re-initiating with the same presignature. Participants have no in-library mechanism to detect or prevent this. The `Clone + Serialize + Deserialize` derivations make it straightforward to persist and replay presignatures across sessions.

### Recommendation

Enforce single-use at the API level by consuming `PresignOutput` by value in `rerandomize_presign`:

```rust
pub fn rerandomize_presign(
    presignature: PresignOutput,   // consumed by value
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

Additionally, remove the `Clone` derive from `PresignOutput` in both schemes so that callers cannot duplicate the value before passing it. The `Serialize`/`Deserialize` derives may be retained for transport but should be accompanied by documentation that deserialization of a previously-used presignature is a critical security violation. A usage-tracking wrapper type (analogous to the `increaseNonce()` fix in the reference report) could also be provided to let callers register and check whether a given presignature (identified by its public `big_r`) has already been consumed.

### Proof of Concept

```rust
// Malicious coordinator scenario (Robust ECDSA)
let presign_out: PresignOutput = /* result of presigning protocol */;

// Session 1: coordinator provides args1 with msg_hash = h1
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args1).unwrap();
// ... collect all s_i shares for h1, then abort without completing

// Session 2: coordinator provides args2 with msg_hash = h2 ≠ h1
// presign_out is still valid — it was never consumed
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args2).unwrap();
// ... collect all s_i shares for h2

// Coordinator now has (R1, s1) and (R2, s2) from the same nonce k.
// Standard nonce-reuse: x = (s1*h2 - s2*h1) / (s1*Rx2 - s2*Rx1) (mod q)
// (exact formula depends on rerandomization deltas, but the algebraic relationship holds)
```

The `PresignOutput` struct is never consumed because `rerandomize_presign` takes `&PresignOutput`, and `Clone` allows duplication before any attempted destruction. [9](#0-8) [10](#0-9)

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

**File:** src/ecdsa/ot_based_ecdsa/README.md (L12-12)
```markdown
Each output is consumed **exactly once** (one-time use).
```

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L70-73)
```markdown
It's **critical** that the output is then destroyed, so that no other
group of parties attempts to re-use that output for another phase.
In particular, the parties need some way of agreeing on which
outputs have been created and used.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L150-154)
```markdown
be aware that it is vulnerable to **split-view attacks** in the robust setting when the
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
