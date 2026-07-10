### Title
Missing `msg_hash == 0` Validation in OT-Based ECDSA `sign` Allows Threshold Signature Over Attacker-Chosen Zero Input — (`src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

The OT-based ECDSA `sign` function accepts a zero `msg_hash` without any rejection, while the robust ECDSA `sign` function explicitly rejects it. A malicious coordinator can initiate a signing session with `msg_hash = 0`, causing all participants to produce signature shares over the zero message hash and yielding a cryptographically valid threshold ECDSA signature for an attacker-chosen input.

---

### Finding Description

The `sign` function in `src/ecdsa/ot_based_ecdsa/sign.rs` performs several input validations — participant count, threshold bounds, coordinator membership — but contains **no check that `msg_hash` is non-zero**: [1](#0-0) 

The function's own documentation acknowledges the risk:

> **WARNING** You must absolutely hash an actual message before passing it to this function. Allowing the signing of arbitrary scalars *is* a security risk, and this function only tolerates this risk to allow for genericity. [2](#0-1) 

Despite this warning, no enforcement exists for

### Citations

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L17-21)
```rust
/// The signature protocol, allowing us to use a presignature to sign a message.
///
/// **WARNING** You must absolutely hash an actual message before passing it to
/// this function. Allowing the signing of arbitrary scalars *is* a security risk,
/// and this function only tolerates this risk to allow for genericity.
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
