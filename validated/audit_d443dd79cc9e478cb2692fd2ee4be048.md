### Title
Missing `msg_hash != 0` Validation in OT-Based ECDSA `sign()` Enables Presign Secret Disclosure to Malicious Coordinator - (File: `src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

The OT-based ECDSA `sign()` function accepts a zero `msg_hash` without any enforcement check, unlike the robust ECDSA `sign()` function which explicitly rejects `msg_hash == 0` to prevent secret leakage. When a malicious coordinator invokes `sign()` with `msg_hash = 0`, honest participants compute and transmit signature shares that reduce to `lambda_i * r * sigma_i`, directly exposing their individual shares of the presign secret `sigma = k * x`. The coordinator can then reconstruct the full presign secret `sigma` via Lagrange interpolation.

---

### Finding Description

**Root cause — missing guard in OT-based ECDSA `sign()`:**

`src/ecdsa/ot_based_ecdsa/sign.rs` lines 22–76 accept any `msg_hash: Scalar` with no zero-value check:

```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,          // ← no is_zero() guard
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
``` [1](#0-0) 

**Contrast — robust ECDSA `sign()` enforces the check:**

`src/ecdsa/robust_ecdsa/sign.rs` lines 91–94 explicitly reject a zero message hash with the stated rationale of preventing split-view attacks:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
    ));
}
``` [2](#0-1) 

**How the share computation leaks `sigma_i` when `msg_hash = 0`:**

`compute_signature_share` in `src/ecdsa/ot_based_ecdsa/sign.rs` lines 139–159 computes:

```rust
let lambda = participants.lagrange::<Secp256K1Sha256>(me)?;
let k_i    = lambda * presignature.k;
let sigma_i = lambda * presignature.sigma;
let r = x_coordinate(&presignature.big_r);
Ok(msg_hash * k_i + r * sigma_i)
``` [3](#0-2) 

When `msg_hash = 0` the `k_i` term vanishes and the share collapses to:

```
s_i = lambda_i * r * sigma_i
```

`r` is the public x-coordinate of `big_r`, and `lambda_i` is a public Lagrange coefficient derived from the known participant list. The coordinator therefore recovers:

```
sigma_i = s_i / (lambda_i * r)
```

for every participant, because each participant sends their share privately to the coordinator:

```rust
chan.send_private(wait0, coordinator, &s_i)?;
``` [4](#0-3) 

Applying Lagrange interpolation over all recovered `sigma_i` values reconstructs the full presign secret `sigma = k * x`.

---

### Impact Explanation

`sigma = k * x` is the product of the per-session nonce `k` and the long-term private key `x`. It is a presign secret that is secret-shared precisely to prevent any single party from learning it. Full reconstruction of `sigma` by the coordinator constitutes **disclosure of presign secret material**, matching the allowed Critical/High impact:

> *"Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets."*

Additionally, if the coordinator can arrange presignature reuse (a separately documented risk), they can combine knowledge of `sigma = k * x` with a second signing under the same presignature at a known `msg_hash = h` to recover `k` and then the private key `x = sigma / k`.

---

### Likelihood Explanation

The coordinator is a fully trusted role in the OT-based ECDSA protocol — any participant can act as coordinator. A malicious coordinator is an explicitly in-scope threat. The attack requires only that the coordinator supply `msg_hash = Scalar::ZERO` at call time, which is a single-field substitution with no other preconditions. No cryptographic break, leaked key, or external dependency is required.

---

### Recommendation

Add the same zero-hash guard that already exists in the robust ECDSA `sign()` function:

```rust
// In src/ecdsa/ot_based_ecdsa/sign.rs, inside sign(), after participant checks:
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0: signing with a zero hash reveals presign secret shares".to_string(),
    ));
}
```

This mirrors the existing enforcement in `src/ecdsa/robust_ecdsa/sign.rs` lines 91–94 and closes the asymmetric validation gap between the two ECDSA variants. [2](#0-1) 

---

### Proof of Concept

**Setup:** 3 participants `[P1, P2, P3]`, threshold 2. Coordinator is `P1` (malicious). Presignature `(big_r, k_i, sigma_i)` distributed honestly.

**Attack steps:**

1. Malicious coordinator `P1` calls `sign(participants, P1, threshold, P1, public_key, presignature, Scalar::ZERO)`.
2. Honest participants `P2` and `P3` each call `sign(...)` with the same `msg_hash = Scalar::ZERO` (they have no way to know the coordinator is malicious at this layer).
3. `P2` computes `s_2 = lambda_2 * r * sigma_2` and sends it privately to `P1`.
4. `P3` computes `s_3 = lambda_3 * r * sigma_3` and sends it privately to `P1`.
5. `P1` computes its own `s_1 = lambda_1 * r * sigma_1`.
6. `P1` recovers `sigma_i = s_i / (lambda_i * r)` for `i ∈ {1, 2, 3}` — all quantities on the right are known to `P1`.
7. `P1` applies Lagrange interpolation: `sigma = sum_i(sigma_i)` (already linearized), reconstructing the full presign secret `sigma = k * x`.

The honest participants complete the protocol without error; the only observable outcome is a valid (or invalid) signature. The secret leakage is silent.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L22-30)
```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L90-93)
```rust
    // Spec 1.4
    let wait0 = chan.next_waitpoint();
    chan.send_private(wait0, coordinator, &s_i)?;

```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L139-159)
```rust
fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    presignature: &RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<Scalar, ProtocolError> {
    // Round 1
    // Linearize ki
    // Spec 1.1
    let lambda = participants.lagrange::<Secp256K1Sha256>(me)?;
    let k_i = lambda * presignature.k;

    // Linearize sigmai
    // Spec 1.2
    let sigma_i = lambda * presignature.sigma;

    // Compute si = h * ki + Rx * sigmai
    // Spec 1.3
    let r = x_coordinate(&presignature.big_r);
    Ok(msg_hash * k_i + r * sigma_i)
}
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L91-95)
```rust
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```
