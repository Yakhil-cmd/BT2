### Title
Presignature Single-Use Not Enforced at API Level Enables Nonce Reuse and Private Key Extraction — (File: `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both ECDSA schemes expose `PresignOutput` and `RerandomizedPresignOutput` as freely `Clone`-able types, and `rerandomize_presign` accepts `&PresignOutput` (a shared reference) rather than consuming it. The library documents that presignatures must never be reused, but provides no API-level enforcement. A malicious coordinator can call `rerandomize_presign` on the same `PresignOutput` with two different `(h, ε)` pairs, initiate two signing sessions against honest participants who have no library-provided mechanism to detect reuse, and recover the aggregate private key from the resulting signatures.

---

### Finding Description

Both `ot_based_ecdsa::PresignOutput` and `robust_ecdsa::PresignOutput` derive `Clone`: [1](#0-0) [2](#0-1) 

`RerandomizedPresignOutput` for both schemes also derives `Clone`: [3](#0-2) [4](#0-3) 

`rerandomize_presign` takes `&PresignOutput` (a shared reference), not ownership, so the same presignature can be rerandomized an unlimited number of times with different signing contexts: [5](#0-4) [6](#0-5) 

Although `sign` takes `RerandomizedPresignOutput` by value, the `Clone` bound means callers can trivially clone before passing, defeating any consumption-based protection. The library provides no unique presignature identifier, no "used" flag, and no consumption mechanism that would allow honest participants to detect that a presignature has already been spent.

The documentation explicitly acknowledges the catastrophic consequence of reuse: [7](#0-6) 

And mandates single-use without providing any enforcement: [8](#0-7) [9](#0-8) 

---

### Impact Explanation

When the same presignature nonce `k` underlies two signing sessions for different messages `h1` and `h2`, the resulting ECDSA signatures `(R, s1)` and `(R, s2)` satisfy:

```
s1 = k_inv * (h1 + x * Rx)
s2 = k_inv * (h2 + x * Rx)
```

Subtracting: `s1 - s2 = k_inv * (h1 - h2)`, so `k = (h1 - h2) / (s1 - s2)`, and then `x = (s1 * k - h1) / Rx`. The aggregate private key is fully recovered. The robust ECDSA documentation further notes a novel split-view variant requiring only `2t+2` presigning participants and two signing sessions.

**Impact: Critical — extraction of the aggregate private signing key.**

---

### Likelihood Explanation

The `rerandomize_presign` API signature (`&PresignOutput`) makes reuse the path of least resistance: a coordinator who stores presignatures (e.g., in a database or cache for retry logic) will naturally call `rerandomize_presign` again on a failed or retried session without any compiler or runtime warning. The library provides no presignature handle, token, or consumption primitive that would guide callers toward correct single-use behavior. Honest participants have no library-provided mechanism to detect that a coordinator is presenting the same presignature context twice.

**Likelihood: Medium** — requires a malicious or buggy coordinator; honest participants cannot independently detect reuse without out-of-band tracking the library does not supply.

---

### Recommendation

1. Change `rerandomize_presign` to consume `PresignOutput` by value (`presignature: PresignOutput`) so that Rust's ownership system enforces single-use at the call site.
2. Remove `Clone` from `PresignOutput` and `RerandomizedPresignOutput` (or gate it behind a clearly named `unsafe`/`#[allow(presignature_clone)]` escape hatch with a documented warning).
3. Introduce an opaque presignature handle type that wraps the secret material and is `!Clone`, ensuring the compiler rejects any attempt to reuse it.

---

### Proof of Concept

```rust
// Malicious coordinator or buggy caller:
let presign_out: PresignOutput = /* result of presigning protocol */;

// rerandomize_presign takes &PresignOutput — does NOT consume it
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args_h1).unwrap();
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args_h2).unwrap();

// Both signing sessions proceed with the same underlying nonce k.
// Coordinator collects (R, s1) for h1 and (R, s2) for h2.
// Private key x = (s1*k - h1) / Rx, where k = (h1-h2)/(s1-s2).
``` [10](#0-9) [11](#0-10)

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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L54-63)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our rerandomized share of the nonce value.
    pub k: Scalar,
    /// Our rerandomized share of the sigma value.
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

**File:** src/ecdsa/robust_ecdsa/mod.rs (L42-52)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    #[zeroize(skip)]
    big_r: AffinePoint,

    /// Our rerandomized secret shares of the nonces.
    e: Scalar,
    alpha: Scalar,
    beta: Scalar,
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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-177)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.
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
