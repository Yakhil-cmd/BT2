### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing Allows Denial of Signing - (File: src/frost/mod.rs)

### Summary
`assert_sign_inputs` in `src/frost/mod.rs` validates only the upper bound of the `threshold` parameter (`threshold > participants.len()`), but omits the lower-bound check (`threshold < 2`) that is consistently enforced in every other protocol entry point in the codebase. A malicious caller can pass `threshold = 0` or `threshold = 1` to any FROST signing entry point, bypassing the guard and causing the signing protocol to produce an unusable/invalid signature or a runtime aggregation failure, permanently denying signing for that round.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on `threshold`:

```rust
// src/dkg.rs:573-581
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

`validate_triple_inputs` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs` also enforces both bounds:

```rust
// generation.rs:693-703
if threshold_value > participants.len() { ... ThresholdTooLarge }
if threshold_value < 2 { ... ThresholdTooSmall }
```

However, `assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound:

```rust
// src/frost/mod.rs:144-150
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
// ← lower-bound check (threshold < 2) is absent
``` [1](#0-0) [2](#0-1) 

`assert_sign_inputs` is the sole validation gate for all three FROST signing entry points:

- `frost::eddsa::sign::sign_v1` and `sign_v2` — `src/frost/eddsa/sign.rs` lines 47 and 73
- `frost::redjubjub::sign::sign` — `src/frost/redjubjub/sign.rs` line 50 [3](#0-2) [4](#0-3) 

### Impact Explanation

When `threshold = 1` is accepted by `assert_sign_inputs`, the FROST `KeyPackage` is constructed with `min_signers = 1`. The FROST aggregation step then attempts to reconstruct the secret using Lagrange interpolation over a single share with coefficient 1, which is not the actual secret (the key was generated with `threshold >= 2`). The resulting signature fails verification against the group public key. The coordinator's output for that signing round is an unusable cryptographic output, permanently denying signing for honest parties in that session.

This matches: **High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation

The threshold parameter is caller-supplied at every FROST signing invocation. Any participant acting as coordinator, or any library integrator who misconfigures the threshold (intentionally or accidentally), can trigger this path. No special privilege beyond being a signing participant is required. The missing check is a single-line omission that is inconsistent with every other validation function in the codebase, making accidental triggering plausible as well.

### Recommendation

Add the lower-bound check to `assert_sign_inputs` in `src/frost/mod.rs`, mirroring `assert_key_invariants`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
``` [5](#0-4) 

### Proof of Concept

1. A key is generated with `threshold = 2` and `participants = [P1, P2, P3]` via `keygen` (enforced minimum of 2 by `assert_key_invariants`).
2. A presignature is generated normally.
3. The coordinator calls `frost::eddsa::sign::sign_v1(participants, threshold=1, me, coordinator, keygen_output, message, rng)`.
4. `assert_sign_inputs` is called: `1 > 3` is false, so no error is returned — the protocol proceeds.
5. The FROST `KeyPackage` is built with `min_signers = 1`.
6. The coordinator aggregates using only its own share (Lagrange coefficient = 1), producing a signature `σ` that does not satisfy the verification equation for the group public key generated at `threshold = 2`.
7. The signing round produces an unusable signature; honest parties cannot obtain a valid signature for this session. [1](#0-0) [6](#0-5) [7](#0-6)

### Citations

**File:** src/frost/mod.rs (L119-160)
```rust
/// Verifies that the sign inputs are valid
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
    let threshold = threshold.into();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
    Ok(participants)
}
```

**File:** src/dkg.rs (L558-582)
```rust
pub fn assert_key_invariants(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<ParticipantList, InitializationError> {
    let threshold = usize::from(threshold.into());
    // need enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // Step 1.1
    // validate threshold
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/frost/eddsa/sign.rs (L37-62)
```rust
pub fn sign_v1(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::new();
    let chan = comms.shared_channel();
    let fut = fut_wrapper_v1(
        chan,
        participants,
        threshold,
        me,
        coordinator,
        keygen_output,
        message,
        rng,
    );
    Ok(make_protocol(comms, fut))
}
```

**File:** src/frost/redjubjub/sign.rs (L49-51)
```rust
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

```
