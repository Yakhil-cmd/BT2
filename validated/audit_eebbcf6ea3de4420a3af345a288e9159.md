### Title
Missing `msg_hash == 0` Validation in OT-Based ECDSA `sign` Initialization - (File: `src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

The OT-based ECDSA `sign` initialization function accepts a zero `msg_hash` without rejection. The robust ECDSA counterpart explicitly guards against this with an `InitializationError`. A malicious caller or coordinator can invoke the OT-based signing protocol with `msg_hash = 0`, producing a valid ECDSA threshold signature that does not commit to any message, and revealing the product `sigma = k * x` (nonce × private key) to the coordinator.

---

### Finding Description

`src/ecdsa/ot_based_ecdsa/sign.rs` `sign()` performs several initialization checks — participant count, duplicates, self-presence, coordinator-presence, threshold size — but **never checks whether `msg_hash` is zero**: [1](#0-0) 

By contrast, the robust ECDSA `sign` function in `src/ecdsa/robust_ecdsa/sign.rs` explicitly rejects a zero `msg_hash` at initialization, citing split-view attack risk: [2](#0-1) 

The signing formula used in the OT-based scheme is:

```
s_i = msg_hash * k_i + r * sigma_i
``` [3](#0-2) 

When `msg_hash = 0`, this collapses to:

```
s_i = r * sigma_i
```

The coordinator sums all shares to obtain `s = r * sigma`, where `sigma = k * x` (nonce × private key). The resulting `(R, s)` pair satisfies ECDSA verification for `msg_hash = 0`:

- `u1 = 0 / s = 0`
- `u2 = r / s = 1 / (k * x)`
- `R' = u1·G + u2·X = (1/k)·G = R` ✓

The signature is valid and accepted by any standard ECDSA verifier. The coordinator also learns `sigma = s / r = k * x`, the product of the nonce and private key.

---

### Impact Explanation

**Critical — Unauthorized creation of a valid threshold signature for attacker-chosen inputs.**

A caller passing `msg_hash = Scalar::ZERO` obtains a fully valid ECDSA threshold signature that does not bind to any message. This signature verifies against the group's public key for the zero-hash input. Additionally, the coordinator learns `sigma = k * x`, partial secret material linking the nonce to the private key. In a split-view scenario (malicious coordinator routes `msg_hash = 0` to some participants and `msg_hash = m` to others), the coordinator can combine shares from both views to reconstruct a signature on `m` without honest participants' consent, bypassing the threshold guarantee.

---

### Likelihood Explanation

The `sign` function is a public API entry point. Any caller — including a malicious application layer, a compromised coordinator, or a participant acting as coordinator — can supply `msg_hash = Scalar::ZERO` directly. No special privilege or cryptographic capability is required. The robust ECDSA variant's explicit guard confirms the library authors are aware of the zero-hash risk; the omission in the OT-based variant is an inconsistency that is trivially exploitable.

---

### Recommendation

Add the same zero-hash guard present in the robust ECDSA `sign` to the OT-based ECDSA `sign`, immediately after the threshold check:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0".to_string(),
    ));
}
``` [4](#0-3) 

---

### Proof of Concept

1. Call `ecdsa::ot_based_ecdsa::sign::sign(participants, coordinator, threshold, me, public_key, presignature, Scalar::ZERO)`.
2. The function passes all existing checks and returns `Ok(protocol)`.
3. Running the protocol produces a `Signature { big_r: R, s }` where `s = r * k * x`.
4. Verify with any standard ECDSA verifier against the group public key and `msg_hash = 0` — verification succeeds.
5. The coordinator computes `sigma = s / r = k * x`, recovering the product of the nonce and private key from the protocol output. [5](#0-4) [6](#0-5)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L22-76)
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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L139-158)
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
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L29-95)
```rust
/// To reduce risk in this implementation, require `N1 = N2 = 2 * max_malicious + 1`,
/// ensure all participants agree on `(msg_hash, tweak, participants)` when creating
/// `RerandomizedPresignOutput`, never reuse a presignature, and do not sign with
/// `msg_hash == 0`.
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: impl Into<MaxMalicious>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
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

    // ensure number of participants during the signing phase is >= 2 * max_malicious + 1
    let robust_ecdsa_threshold = max_malicious
        .into()
        .value()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            InitializationError::BadParameters(
                "2*threshold+1 must be less than usize::MAX".to_string(),
            )
        })?;
    if robust_ecdsa_threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "2*max_malicious+1 must be less than or equals to participant count".to_string(),
        ));
    }

    // The next two conditions prevent split-view attacks
    // documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during signing must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```
