### Title
Presignature Replay After Failed or Aborted Signing Session Enables Secret Key Extraction — (`src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both the OT-based and Robust ECDSA schemes document a strict one-time-use requirement for presignatures, yet the library provides no enforcement of this invariant. `PresignOutput` derives `Clone + Serialize + Deserialize`, and `rerandomize_presign` accepts a non-consuming `&PresignOutput` reference. A malicious coordinator can reuse the same presignature across two signing sessions — including after a failed or aborted session — obtaining two sets of signature shares for the same underlying nonce. This is a classic ECDSA nonce-reuse attack that allows full secret key extraction.

---

### Finding Description

The library explicitly documents the one-time-use requirement in multiple places:

- `docs/ecdsa/robust_ecdsa/signing.md` line 176: *"Never reuse a presignature, even across failed, aborted, or partially completed signing sessions."*
- `docs/ecdsa/ot_based_ecdsa/orchestration.md` lines 70–71: *"It's critical that the output is then destroyed, so that no other group of parties attempts to re-use that output for another phase."*

Despite this, the library provides no mechanism to enforce it.

**Root cause 1 — `PresignOutput` is freely cloneable and serializable:**

OT-based:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }
``` [1](#0-0) 

Robust:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }
``` [2](#0-1) 

**Root cause 2 — `rerandomize_presign` takes a non-consuming `&PresignOutput` reference:**

OT-based:
```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← borrow, not move
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { ... }
``` [3](#0-2) 

Robust:
```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← borrow, not move
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { ... }
``` [4](#0-3) 

Because `rerandomize_presign` borrows rather than consumes the presignature, the original `PresignOutput` remains intact and can be passed to `rerandomize_presign` again with different `RerandomizationArguments` (different `msg_hash`, `tweak`, or `entropy`). The `Clone + Serialize + Deserialize` derivation further allows the presignature to be stored, serialized to disk, and replayed across process restarts or network failures.

The security documentation itself confirms the consequence:

> *"If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks."* [5](#0-4) 

---

### Impact Explanation

A malicious coordinator who participates in presigning holds a `PresignOutput`. By calling `rerandomize_presign` twice on the same `PresignOutput` with different `(msg_hash, tweak, entropy)` tuples, the coordinator obtains two `RerandomizedPresignOutput` values whose underlying nonce `k` is the same (scaled by different `delta` values). The coordinator then runs two signing sessions, collecting all participants' signature shares for both sessions. With two ECDSA signatures sharing a multiplicatively related nonce, the coordinator can solve for the aggregate secret key `x` using standard nonce-reuse algebra.

This satisfies the **Critical** impact: *"Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets."*

---

### Likelihood Explanation

The malicious coordinator is an explicitly in-scope attacker profile. The coordinator is a required participant in every signing session and naturally holds a `PresignOutput` after presigning. No external assumptions, leaked keys, or cryptographic breaks are required. The attack requires only:

1. Participation in one presigning session (to obtain `PresignOutput`).
2. Initiating two signing sessions using the same `PresignOutput` — trivially achievable since `PresignOutput` is `Clone` and `rerandomize_presign` does not consume it.
3. Collecting the honest participants' signature shares from both sessions (which participants send unconditionally upon receiving a valid signing request).

The attack is reachable in any deployment where the coordinator role is not fully trusted, which is the standard adversarial model for threshold signing.

---

### Recommendation

1. **Consume `PresignOutput` on rerandomization.** Change `rerandomize_presign` to take `PresignOutput` by value (move semantics) rather than by reference. This makes the Rust type system enforce one-time use at the call site:

   ```rust
   pub fn rerandomize_presign(
       presignature: PresignOutput,  // ← move, not borrow
       args: &RerandomizationArguments,
   ) -> Result<Self, ProtocolError>
   ```

2. **Remove `Clone` from `PresignOutput`.** Removing the `Clone` derive prevents callers from duplicating a presignature before passing it to `rerandomize_presign`, closing the bypass of move semantics.

3. **Remove `Serialize`/`Deserialize` from `PresignOutput`, or add a usage-tracking wrapper.** If serialization is required for persistence, wrap `PresignOutput` in a type that marks itself as consumed upon deserialization and use, preventing replay across process restarts.

---

### Proof of Concept

**Setup:** Robust ECDSA, `t = 1`, `N = 3` participants `{P1, P2, P3}`, coordinator `P1`.

**Step 1 — Presigning:** All three parties run `presign(...)` and each obtains their `PresignOutput` share. The coordinator `P1` holds `presign_out_1: PresignOutput`.

**Step 2 — First signing session (message `h1`):**

```rust
// P1 (coordinator) rerandomizes with args1 (msg_hash = h1, entropy = e1)
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presign_out_1, &args1)?;
// P1 initiates sign(...) with rerand1 and h1
// P2 and P3 send their signature shares s2^1 and s3^1 to P1
// P1 aborts — does NOT publish the signature
```

**Step 3 — Second signing session (message `h2`, same presignature):**

```rust
// presign_out_1 is still valid — rerandomize_presign did not consume it
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presign_out_1, &args2)?;
// P1 initiates sign(...) with rerand2 and h2
// P2 and P3 send their signature shares s2^2 and s3^2 to P1
```

**Step 4 — Key extraction:** P1 now holds two complete sets of signature shares for the same underlying nonce `k` (scaled by `delta1` and `delta2` respectively). Using the known relationship `R2 = delta2/delta1 * R1` and the two signing equations:

```
s^1 = h1 * (k/delta1) + Rx1 * (sigma/delta1)
s^2 = h2 * (k/delta2) + Rx2 * (sigma/delta2)
```

P1 can solve for the aggregate secret key `x` (embedded in `sigma = k*x + ...`) using standard ECDSA nonce-reuse algebra, as confirmed by the library's own security documentation. [6](#0-5) [7](#0-6) [1](#0-0)

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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-177)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.
```
