### Title
Presignature One-Time-Use Constraint Unenforced at API Level — (`src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both `RerandomizedPresignOutput::rerandomize_presign` implementations accept `presignature: &PresignOutput` (a shared reference) rather than consuming the value by ownership. Additionally, `PresignOutput` derives `Clone`. Together, these mean the library provides no mechanism to enforce the documented "one-time use" constraint on presignatures. A malicious coordinator can rerandomize the same `PresignOutput` with multiple distinct `(h, ε, ρ)` tuples, run parallel signing sessions, and recover the aggregate private key via standard ECDSA nonce-reuse algebra.

---

### Finding Description

The OT-based ECDSA presignature rerandomization function is:

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs
pub fn rerandomize_presign(
    presignature: &PresignOutput,       // shared reference — not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
``` [1](#0-0) 

The robust ECDSA variant is identical in structure:

```rust
// src/ecdsa/robust_ecdsa/mod.rs
pub fn rerandomize_presign(
    presignature: &PresignOutput,       // shared reference — not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
``` [2](#0-1) 

Both `PresignOutput` types also derive `Clone`: [3](#0-2) [4](#0-3) 

Because `rerandomize_presign` borrows rather than consumes the presignature, Rust's ownership system cannot prevent a caller from invoking it twice (or more) on the same `PresignOutput`. The `Clone` derive makes this even more explicit: even a hypothetical future change to consume by value would be trivially bypassed with `.clone()`.

The library's own security documentation acknowledges the catastrophic consequence:

> If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks. [5](#0-4) 

The orchestration documentation also states:

> It's **critical** that the output is then destroyed, so that no other group of parties attempts to re-use that output for another phase. [6](#0-5) 

Yet the code provides no destruction or invalidation mechanism whatsoever.

**Analog to the external report:** In the anchor contracts, `config.spend_limit` is checked before each spend but never decremented, so the limit can be bypassed by repeated calls. Here, the presignature's "one-time use" invariant is documented but never enforced: `rerandomize_presign` checks nothing about prior use and updates no "used" state, so the same presignature can be rerandomized and signed with an unlimited number of times.

---

### Impact Explanation

When the same `PresignOutput` (with its fixed nonce point `R = g^k`) is rerandomized under two different `RerandomizationArguments` `(h₁, ε₁, ρ₁)` and `(h₂, ε₂, ρ₂)`, the resulting `RerandomizedPresignOutput` values share the same underlying nonce scalar `k` (scaled by different `δ⁻¹` values). Two completed signing sessions then yield two ECDSA signatures `(R', s₁)` and `(R'', s₂)` whose nonces are algebraically related. Standard ECDSA nonce-reuse linear algebra recovers the aggregate secret key `x`. This is a **Critical** impact: full extraction of the aggregate private signing key.

---

### Likelihood Explanation

The entry path requires only a single party (e.g., the coordinator or any participant who holds a `PresignOutput`) to call `rerandomize_presign` twice with different arguments. No cryptographic capability is needed. The `PresignOutput` is a plain serializable struct with `pub` fields, and the function is a public API. Any library caller — including a malicious coordinator orchestrating two signing sessions — can trigger this with two lines of code.

---

### Recommendation

1. **Consume by value:** Change both `rerandomize_presign` signatures to take `presignature: PresignOutput` (owned), so Rust's move semantics prevent reuse without an explicit `.clone()`.
2. **Remove or gate `Clone`:** Remove the `Clone` derive from `PresignOutput` (both OT-based and robust variants), or replace it with a deliberately named `unsafe_clone_for_testing` method, so accidental duplication is not possible in production paths.
3. **Wrap in a single-use type:** Introduce a `OneTimePresignOutput` newtype that implements `Into<PresignOutput>` but not `Clone`, and require all signing APIs to accept only this type.

---

### Proof of Concept

```rust
// Attacker (malicious coordinator) holds a single PresignOutput
let presign_out: PresignOutput = /* obtained from presigning protocol */;

// Rerandomize the SAME presignature for two different messages
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args1).unwrap();
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args2).unwrap();
// presign_out is still valid here — it was never consumed

// Run two parallel signing sessions using rerand1 and rerand2
// Both sessions complete successfully, yielding (R1, s1) and (R2, s2)
// The nonces are algebraically related (both derived from the same k)
// Standard ECDSA nonce-reuse equations recover the private key x
``` [7](#0-6) [8](#0-7)

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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L149-158)
```markdown
Before implementing or using the robust ECDSA scheme implemented here,
be aware that it is vulnerable to **split-view attacks** in the robust setting when the
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.

Moreover, due to protocol modifications relative to [[DJNPO20](https://eprint.iacr.org/2020/501)] (notably signature-share
linearization), **a novel split-view attack exists that can extract the secret key using as
few as $2t + 2$ presigning participants**, with as few as two signing sessions.
```

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L64-79)
```markdown
## Discarding information

Each phase can be run many times in advance, recording the information
public information produced, as well as the list of parties which produced it.
Then, this output is consumed by having a set of parties use it
for a subsequent phase.
It's **critical** that the output is then destroyed, so that no other
group of parties attempts to re-use that output for another phase.
In particular, the parties need some way of agreeing on which
outputs have been created and used.
If the threshold $t_i$ is such that $N_{i} \leq 2t - 1$, then it's impossible
to have two non-overlapping quorums, so if each party locally registers the
fact that an output has been used, then agreement can be had not to
use a certain output.
Otherwise, you might have two independent groups of parties trying
to use the same output, which is bad.
```
