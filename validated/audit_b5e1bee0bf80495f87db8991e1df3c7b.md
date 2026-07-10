### Title
Zero `msg_hash` Accepted Without Rejection Discloses Aggregate Presign Secret `σ = k·x` in OT-Based ECDSA Sign — (`src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

The OT-based ECDSA `sign` function accepts `msg_hash = 0` (the zero scalar) without any guard. When `msg_hash = 0`, the signature-share formula collapses to `s_i = r · σ_i`, so the coordinator-aggregated signature `s = r · σ` directly encodes the aggregate presign secret `σ = k · x`. Because `r` is public, any observer can recover `σ = s / r`, disclosing the product of the signing nonce and the master private key. The robust ECDSA counterpart in the same repository explicitly rejects this input; the OT-based path does not.

---

### Finding Description

`src/ecdsa/ot_based_ecdsa/sign.rs` exposes a public `sign` function that accepts an arbitrary `msg_hash: Scalar` from the caller:

```rust
// lines 17-22
/// **WARNING** You must absolutely hash an actual message before passing it to
/// this function. Allowing the signing of arbitrary scalars *is* a security risk,
/// and this function only tolerates this risk to allow for genericity.
pub fn sign(
    ...
    msg_hash: Scalar,
``` [1](#0-0) 

The only input checks performed are participant-list sanity checks; there is **no** `msg_hash.is_zero()` guard anywhere in the function or in the downstream helpers it calls. [2](#0-1) 

The per-participant signature share is computed in `compute_signature_share`:

```rust
// line 158
Ok(msg_hash * k_i + r * sigma_i)
``` [3](#0-2) 

When `msg_hash = 0` this reduces to:

```
s_i = 0 · k_i + r · σ_i  =  r · σ_i
```

After Lagrange-weighted summation across all `N` participants the coordinator obtains:

```
s = Σ s_i = r · Σ(λ_i · σ_i) = r · σ
```

where `σ = k · x` is the aggregate presign secret (nonce × master private key), confirmed by the test setup:

```rust
// test lines 217-218
let sigma = k * x;
let h = Polynomial::generate_polynomial(Some(sigma), degree, &mut rng).unwrap();
``` [4](#0-3) 

Because `r = x_coordinate(R)` is the public x-coordinate of the nonce point, any observer of the output signature can compute:

```
σ = s / r  =  k · x
```

This is a full disclosure of the aggregate presign secret.

By contrast, the robust ECDSA `sign` function in the same repository explicitly rejects this input:

```rust
// robust_ecdsa/sign.rs lines 91-95
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
    ));
}
``` [5](#0-4) 

The OT-based path has no equivalent guard.

---

### Impact Explanation

**Critical — Disclosure of aggregate presign secret material.**

The output signature `(R, s)` with `h = 0` satisfies `s = r · k · x`. Since `r` is public, the value `σ = k · x` is immediately recoverable as `s / r`. `σ` is the aggregate presign secret: it is the product of the one-time signing nonce `k` and the master private key `x`. Its disclosure:

1. **Directly leaks `x` if `k` is ever recovered.** In the OT-based scheme `k` is distributed across shares; however, any future nonce-reuse event, weak-RNG event, or side-channel that exposes `k` immediately yields `x = σ / k`.
2. **Enables cross-session key extraction.** If an attacker can obtain one `h = 0` signature `(R₁, s₁)` and one honest signature `(R₁, s₂)` over the *same* presignature (nonce reuse, which the protocol does not prevent at the API level), then:
   - `s₁ = r₁ · k · x`
   - `s₂ = k · (h₂ + r₁ · x)`
   - `s₂ - r₁ · (s₁ / r₁) = k · h₂`  →  `k = (s₂ - s₁) / h₂`  →  `x = s₁ / (r₁ · k)`
3. **Violates the secrecy invariant of the presignature.** The `sigma` field of `PresignOutput` is a secret share; its aggregate is never supposed to be observable. Signing with `h = 0` makes it directly observable in the output.

---

### Likelihood Explanation

**High.** The `sign` function is part of the public library API. Any unprivileged library caller or malicious coordinator can supply `msg_hash = Scalar::ZERO` directly. No special privilege, network position, or cryptographic capability is required. The WARNING comment in the source acknowledges the risk but provides no enforcement, leaving the door open for accidental or deliberate misuse.

---

### Recommendation

Add the same zero-hash guard that the robust ECDSA path already enforces, immediately after the participant-list checks in `src/ecdsa/ot_based_ecdsa/sign.rs`:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0: signing with a zero hash discloses the presign secret sigma = k*x".to_string(),
    ));
}
```

This mirrors the existing protection in `src/ecdsa/robust_ecdsa/sign.rs` lines 91–95 and closes the disclosure path at the API boundary. [5](#0-4) 

---

### Proof of Concept

```rust
// Attacker calls the public OT-based sign API with msg_hash = 0
let msg_hash = Scalar::ZERO;   // zero scalar, no rejection occurs

// Each participant computes:
//   s_i = 0 * k_i + r * sigma_i  =  r * sigma_i
// Coordinator sums:
//   s = r * sigma   (sigma = k * x, the aggregate presign secret)

// After receiving the valid signature (R, s):
let r = x_coordinate(&sig.big_r);          // public
let sigma = s * r.invert().unwrap();        // sigma = k * x, now fully recovered
// sigma is the aggregate presign secret; if k is later recovered, x = sigma / k
```

The `sign` function at `src/ecdsa/ot_based_ecdsa/sign.rs` line 22 accepts this call without error, proceeds through `compute_signature_share` at line 158, and returns a valid signature that encodes `σ`. [6](#0-5) [7](#0-6)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L17-30)
```rust
/// The signature protocol, allowing us to use a presignature to sign a message.
///
/// **WARNING** You must absolutely hash an actual message before passing it to
/// this function. Allowing the signing of arbitrary scalars *is* a security risk,
/// and this function only tolerates this risk to allow for genericity.
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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L31-76)
```rust
    let threshold = usize::from(threshold.into());
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    // ensure number of participants during the signing phase is >= threshold
    if participants.len() < threshold {
        return Err(InitializationError::NotEnoughParticipantsForThreshold {
            threshold,
            participants: participants.len(),
        });
    }

    let ctx = Comms::new();
    let fut = fut_wrapper(
        ctx.shared_channel(),
        participants,
        coordinator,
        me,
        public_key,
        presignature,
        msg_hash,
    );
    Ok(make_protocol(ctx, fut))
}
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L144-159)
```rust
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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L217-219)
```rust
        let sigma = k * x;

        let h = Polynomial::generate_polynomial(Some(sigma), degree, &mut rng).unwrap();
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L91-95)
```rust
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```
