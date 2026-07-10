### Title
Missing `msg_hash != 0` Validation in OT-Based ECDSA `sign` Allows Unauthorized Threshold Signature for Attacker-Chosen Zero Hash - (`File: src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

The OT-based ECDSA `sign` function accepts `msg_hash = 0` without any validation, while the robust ECDSA `sign` function explicitly rejects it with a documented security rationale. A malicious coordinator can instruct honest participants to sign `msg_hash = 0`, and the library will produce a cryptographically valid threshold ECDSA signature over the zero scalar — an attacker-chosen input — without any protocol-level rejection.

---

### Finding Description

`src/ecdsa/robust_ecdsa/sign.rs` contains an explicit guard:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
    ));
}
``` [1](#0-0) 

The function-level doc comment for robust ECDSA `sign` also explicitly lists "do not sign with `msg_hash == 0`" as a required invariant to prevent split-view attacks. [2](#0-1) 

The OT-based ECDSA `sign` function in `src/ecdsa/ot_based_ecdsa/sign.rs` performs no equivalent check. It validates participant counts, coordinator membership, and threshold bounds, but never checks whether `msg_hash` is zero: [3](#0-2) 

The signature share computation is:

```
s_i = h * k_i + Rx * sigma_i
``` [4](#0-3) 

When `h = 0`, this degenerates to `s_i = Rx * sigma_i`. The aggregate `s = Rx * sigma` where `sigma = k * x` (the product of the nonce and private key). This is a **valid** ECDSA signature for `msg_hash = 0`:

- Verification: `u1 = 0 * s^{-1} = 0`, `u2 = Rx * s^{-1} = Rx * (Rx * k * x)^{-1} = (k * x)^{-1}`
- `u2 * X = (k * x)^{-1} * x * G = k^{-1} * G = R` ✓

The coordinator's final verification step `sig.verify(&public_key, &msg_hash)` passes, and the protocol returns `Ok(Some(sig))`. [5](#0-4) 

---

### Impact Explanation

**Critical — Unauthorized creation of a valid threshold signature for attacker-chosen inputs.**

A malicious coordinator instructs all participants to call `sign()` with `msg_hash = 0`. The library accepts this without error. The resulting `(R, s)` is a fully valid ECDSA signature over the zero scalar, verifiable by any standard ECDSA verifier against the threshold public key. This is a valid threshold signature produced for an input chosen entirely by the attacker, not derived from any legitimate message.

Additionally, if the same presignature `(R, k_i, sigma_i)` is used for both a legitimate signing session with hash `h1` and a second session with `h2 = 0`, the attacker obtains:

- `s1 = h1 * k + Rx * sigma`
- `s2 = Rx * sigma`

From which: `sigma = s2 / Rx`, `k = (s1 - s2) / h1`, and `x = sigma / k` — full private key extraction. The `msg_hash = 0` case uniquely simplifies this computation by directly exposing `sigma` without needing to solve a system of equations.

---

### Likelihood Explanation

**Medium.** In a distributed signing system, participants receive the `msg_hash` value from an orchestration layer or coordinator. A malicious coordinator can supply `msg_hash = 0` to all participants. Because the library imposes no check, each participant's `sign()` call succeeds. The coordinator role is a realistic attacker position in the documented trust model. The only mitigation is application-layer validation outside the library, which the library does not enforce or document for the OT-based variant (unlike the robust variant, which enforces it in-library).

---

### Recommendation

Add the same zero-hash guard to `src/ecdsa/ot_based_ecdsa/sign.rs` that already exists in the robust ECDSA variant:

```rust
if bool::from(msg_hash.is_zero()) {
    return Err(InitializationError::BadParameters(
        "msg_hash cannot be 0".to_string(),
    ));
}
```

Place this check in the `sign()` initialization function alongside the existing participant and threshold validations, before the protocol future is spawned. [6](#0-5) 

---

### Proof of Concept

1. Call `ot_based_ecdsa::sign()` with `msg_hash = Scalar::ZERO` and a valid presignature and participant set.
2. Observe that initialization succeeds (no `InitializationError`).
3. Run the protocol to completion.
4. The coordinator's `do_sign_coordinator` computes `s = 0 * k + Rx * sigma = Rx * sigma`, calls `sig.verify(&public_key, &Scalar::ZERO)`, which passes, and returns `Ok(Some(sig))`.
5. Verify the returned signature against the threshold public key with `msg_hash = 0` using any standard ECDSA verifier — it verifies successfully.

Contrast: calling `robust_ecdsa::sign()` with `msg_hash = Scalar::ZERO` immediately returns `Err(InitializationError::BadParameters("msg_hash cannot be 0 ..."))`. [1](#0-0) [3](#0-2)

### Citations

**File:** src/ecdsa/robust_ecdsa/sign.rs (L29-32)
```rust
/// To reduce risk in this implementation, require `N1 = N2 = 2 * max_malicious + 1`,
/// ensure all participants agree on `(msg_hash, tweak, participants)` when creating
/// `RerandomizedPresignOutput`, never reuse a presignature, and do not sign with
/// `msg_hash == 0`.
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L91-95)
```rust
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```

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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L128-135)
```rust
    // Spec 1.8
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    Ok(Some(sig))
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L155-158)
```rust
    // Compute si = h * ki + Rx * sigmai
    // Spec 1.3
    let r = x_coordinate(&presignature.big_r);
    Ok(msg_hash * k_i + r * sigma_i)
```
