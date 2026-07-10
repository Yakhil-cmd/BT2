### Title
Missing `msg_hash = 0` Validation in OT-Based ECDSA `sign` Initialization - (File: `src/ecdsa/ot_based_ecdsa/sign.rs`)

### Summary
The `ot_based_ecdsa::sign` initialization function does not validate that `msg_hash` is non-zero, while the analogous `robust_ecdsa::sign` function explicitly rejects zero message hashes. A malicious coordinator can pass `msg_hash = 0` to produce a valid threshold ECDSA signature for the zero message hash, bypassing the intended security constraint present in the sibling scheme.

### Finding Description

In `src/ecdsa/ot_based_ecdsa/sign.rs`, the `sign` function accepts `msg_hash: Scalar` without checking if it is zero: [1](#0-0) 

In contrast, `src/ecdsa/robust_ecdsa/sign.rs` explicitly rejects zero message hashes: [2](#0-1) 

The security documentation explicitly states this constraint: [3](#0-2) 

When `msg_hash = 0`, the signature share computation in `compute_signature_share` becomes:

```
s_i = 0 * k_i + r * sigma_i = r * sigma_i
``` [4](#0-3) 

The message hash is completely absent from the signature share. The coordinator sums all shares to get `s = r * sigma` where `sigma = k * x` (nonce times private key). This signature `(R, s)` is cryptographically valid for `msg_hash = 0`.

**Verification that the signature passes `Signature::verify`:**

The verify function computes `reproduced = G * (h * s_inv) + X * (r * s_inv)`. With `h = 0` and `s = r * k * x`:
- `s_inv = 1 / (r * k * x)`
- `reproduced = G * 0 + x*G * (r / (r*k*x)) = G * (1/k) = R`

So `x_coordinate(reproduced) = r` ✓ — the signature verifies. [5](#0-4) 

### Impact Explanation

A malicious coordinator calls `ot_based_ecdsa::sign` with `msg_hash = Scalar::ZERO`. All participants compute signature shares that contain no message information (`s_i = r * sigma_i`). The coordinator aggregates these into a valid ECDSA signature `(R, s)` where `s = r * k * x`. This constitutes **unauthorized creation of a valid threshold signature for an attacker-chosen input** (the zero message hash). Additionally, the resulting signature leaks `k * x = s / r` — the product of the secret nonce and private key — which could be leveraged in further algebraic attacks across multiple signing sessions.

### Likelihood Explanation

The `msg_hash` parameter is directly controlled by the coordinator when calling `sign`. A malicious coordinator can trivially pass `Scalar::ZERO` with no additional prerequisites. The participants have no mechanism to detect or reject this value — the library provides no guard. The attack requires only a single signing session.

### Recommendation

Add a zero check for `msg_hash` in `ot_based_ecdsa::sign`, consistent with the check already present in `robust_ecdsa::sign`:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0".to_string(),
    ));
}
```

This should be placed in the initialization guard block alongside the existing participant and threshold checks. [6](#0-5) 

### Proof of Concept

1. Coordinator calls `ot_based_ecdsa::sign` with `msg_hash = Scalar::ZERO` for all participants.
2. Each participant's `compute_signature_share` computes `s_i = 0 * k_i + r * sigma_i = r * sigma_i`.
3. Coordinator sums: `s = r * Σ(λ_i * sigma_i) = r * sigma = r * k * x`.
4. `Signature::verify` is called with `msg_hash = 0`: `reproduced = G*(0) + X*(r*s_inv) = G*(1/k) = R` → verification passes.
5. A valid threshold ECDSA signature for the zero message hash is returned to the coordinator, with no error raised by the library.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L22-63)
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
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L155-158)
```rust
    // Compute si = h * ki + Rx * sigmai
    // Spec 1.3
    let r = x_coordinate(&presignature.big_r);
    Ok(msg_hash * k_i + r * sigma_i)
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L91-95)
```rust
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L179-181)
```markdown
4. **Do not sign with $h = 0$** (the zero message hash).
   This input enables a related algebraic split-view attack in the modified scheme when
   $N_1 > 2t + 1$.
```

**File:** src/ecdsa/mod.rs (L65-79)
```rust
    pub fn verify(&self, public_key: &AffinePoint, msg_hash: &Scalar) -> bool {
        let r: Scalar = x_coordinate(&self.big_r);
        if r.is_zero().into() || self.s.is_zero().into() {
            return false;
        }
        // Check if s has been normalized
        if self.s.is_high().into() {
            return false;
        }
        // tested earlier is not zero, so inversion will not raise an error and unwrap cannot panic
        let s_inv = self.s.invert_vartime().unwrap();
        let reproduced = (ProjectivePoint::GENERATOR * (*msg_hash * s_inv))
            + (ProjectivePoint::from(*public_key) * (r * s_inv));
        x_coordinate(&reproduced.into()) == r
    }
```
