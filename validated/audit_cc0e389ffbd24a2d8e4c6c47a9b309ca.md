### Title
`PresignOutput` Not Consumed After Rerandomization Enables Nonce Reuse and Secret Key Extraction - (File: `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

`RerandomizedPresignOutput::rerandomize_presign` accepts `presignature: &PresignOutput` (a shared reference) rather than consuming the `PresignOutput` by value. This means the library never invalidates or marks the presignature as used after a successful rerandomization. A caller — or a malicious coordinator orchestrating multiple signing sessions — can rerandomize the same `PresignOutput` multiple times with different messages/tweaks, producing signing sessions whose nonces are multiplicatively related. Two such signatures are sufficient to extract the aggregate secret key.

---

### Finding Description

Both ECDSA variants expose the same root cause.

**OT-based ECDSA** (`src/ecdsa/ot_based_ecdsa/mod.rs`, line 66):

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← shared reference, NOT consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {
``` [1](#0-0) 

The `PresignOutput` struct derives `Clone` and holds secret nonce shares `k: Scalar` and `sigma: Scalar`. [2](#0-1) 

**Robust ECDSA** (`src/ecdsa/robust_ecdsa/mod.rs`) has the identical pattern — `RerandomizedPresignOutput::rerandomize_presign` also takes `&PresignOutput`. [3](#0-2) 

Because the function takes a shared reference, the caller retains full ownership of the `PresignOutput` after the call. Nothing in the library prevents calling `rerandomize_presign` a second time on the same object with different `RerandomizationArguments` (i.e., a different message hash or tweak). The library's own documentation acknowledges this danger but relies entirely on caller discipline:

> "it's crucial that a presignature is never reused" [4](#0-3) 

> "Never reuse a presignature, even across failed, aborted, or partially completed signing sessions." [5](#0-4) 

The rerandomization computes `k_rerandomized = k * delta^{-1}` where `delta` is derived from the message/context. Two rerandomizations of the same `PresignOutput` with different arguments yield nonces `k/delta_1` and `k/delta_2`. The ratio `delta_1/delta_2` is computable from public information, making this a known-relationship nonce reuse — sufficient for full secret key recovery via standard ECDSA algebra.

The security documentation explicitly confirms this attack path:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks." [6](#0-5) 

---

### Impact Explanation

A malicious coordinator can instruct participants to run two signing sessions against the same presignature with different message hashes. Each honest participant calls `rerandomize_presign` twice on their stored `PresignOutput` (the library does not prevent this). The coordinator collects both sets of signature shares, aggregates two valid ECDSA signatures, and uses the known multiplicative relationship between the nonces to solve for the aggregate secret key. This constitutes **extraction of private signing shares / aggregate secret material**.

Impact: **Critical** — matches "Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets."

---

### Likelihood Explanation

The attack requires a malicious coordinator, which is an explicitly modeled adversary in this library (the coordinator is a designated participant in both ECDSA signing protocols). The coordinator needs only to issue two signing requests referencing the same presignature ID before participants locally delete it. Because the library API does not consume the `PresignOutput`, participants have no type-level protection against this. The attack is also reachable through accidental application-layer bugs (e.g., retry logic after a failed signing session reusing the same presignature). Likelihood is **High**.

---

### Recommendation

Change `rerandomize_presign` to consume the `PresignOutput` by value in both ECDSA variants:

```rust
// Before (unsafe — allows reuse):
pub fn rerandomize_presign(
    presignature: &PresignOutput,
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>

// After (safe — enforces single use at the type level):
pub fn rerandomize_presign(
    presignature: PresignOutput,
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

This mirrors the documented invariant ("each output is consumed exactly once") at the type level, making presignature reuse a compile-time error rather than a runtime security assumption. [7](#0-6) 

---

### Proof of Concept

1. Participant P completes presigning and holds `presign_out: PresignOutput` with nonce share `k`.
2. Coordinator sends signing request for message `m1` with tweak `ε1`.
3. P calls `RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args1)` → `rp1` (nonce `k/δ1`). P sends signature share `s1` to coordinator.
4. Coordinator sends a second signing request for message `m2` with tweak `ε2`, referencing the same presignature.
5. P calls `RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args2)` → `rp2` (nonce `k/δ2`). The library does not reject this. P sends signature share `s2` to coordinator.
6. Coordinator aggregates two valid signatures `(R1, s1_agg)` and `(R2, s2_agg)`. Since `R1 = k/δ1 · G` and `R2 = k/δ2 · G`, the ratio `δ1/δ2` is public. The coordinator solves the standard two-equation ECDSA system to recover the aggregate secret key `x`. [8](#0-7)

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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L13-19)
```rust
/// The presignature protocol.
///
/// This is the first phase of performing a signature, in which we perform
/// all the work we can do without yet knowing the message to be signed.
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L150-154)
```markdown
be aware that it is vulnerable to **split-view attacks** in the robust setting when the
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-178)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.

```

**File:** src/ecdsa/ot_based_ecdsa/README.md (L12-12)
```markdown
Each output is consumed **exactly once** (one-time use).
```
