### Title
Missing Minimum Threshold Enforcement in FROST Signing Allows Corrupted Sign Output - (File: `src/frost/mod.rs`)

### Summary
The `assert_sign_inputs` and `presign` functions in `src/frost/mod.rs` do not enforce the minimum threshold of 2 that is explicitly required by the protocol and enforced during DKG in `assert_key_invariants`. A caller can invoke the FROST signing or presigning entry points with `threshold = 1`, bypassing the documented lower bound. Because the Lagrange interpolation in signing is computed over only one participant's share when `threshold = 1`, the aggregated signature is cryptographically invalid and unusable, corrupting the sign output for all honest participants in that session.

### Finding Description
During DKG, `assert_key_invariants` in `src/dkg.rs` enforces both an upper and a lower bound on the threshold:

```rust
// src/dkg.rs lines 572-582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

The signing-phase validation function `assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound:

```rust
// src/frost/mod.rs lines 144-150
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
``` [2](#0-1) 

The `ThresholdTooSmall` guard is entirely absent from `assert_sign_inputs`. [3](#0-2) 

The same omission exists in the `presign` entry point, which validates threshold only against `participants.len()`: [4](#0-3) 

A caller who supplies `threshold = 1` to either entry point passes all validation checks. During FROST signing, the coordinator collects only one participant's signature share and computes the Lagrange coefficient for a singleton set (coefficient = 1). Because the secret was distributed with `threshold ≥ 2` during DKG, the single-share reconstruction is cryptographically incorrect: the aggregated signature does not satisfy the verification equation for the group public key, producing an unusable output.

### Impact Explanation
**High.** Honest participants who join a signing session initiated with `threshold = 1` complete the protocol and receive a signature that fails verification against the public key produced by DKG. The sign output is corrupted — an unusable cryptographic artifact — matching the allowed impact: *"Corruption of … sign … outputs so honest parties accept … unusable cryptographic outputs."*

### Likelihood Explanation
Any library caller who controls the `threshold` argument to `presign` or the signing entry points (e.g., a malicious coordinator or a misconfigured participant) can trigger this with a single parameter change. No privileged key material or cryptographic break is required. The inconsistency between DKG validation and signing validation makes accidental misconfiguration equally plausible alongside deliberate abuse.

### Recommendation
Add the same lower-bound guard that exists in `assert_key_invariants` to both `assert_sign_inputs` and `presign`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing check at `src/dkg.rs` lines 580–582 and closes the inconsistency between the DKG and signing validation paths. [5](#0-4) 

### Proof of Concept

1. Run DKG with `participants = [P1, P2, P3]`, `threshold = 2`. All three parties obtain valid `KeygenOutput` shares and a shared public key `PK`.
2. Call `presign` (or the EdDSA/RedJubjub sign entry point) with the same participant list but `threshold = 1`. Validation passes because `1 ≤ 3` satisfies the only threshold check present.
3. The coordinator collects one signature share (from itself). The Lagrange coefficient for the singleton signing set is 1, so the aggregated share equals the single participant's raw share — not the reconstructed secret.
4. The resulting signature `(R, z)` fails `VerifyingKey::verify` against `PK`, confirming the output is unusable.
5. All honest participants who contributed to this session receive or observe the invalid signature with no protocol-level error, as the corruption occurs silently after the missing guard.

### Citations

**File:** src/dkg.rs (L572-582)
```rust
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

**File:** src/frost/mod.rs (L71-77)
```rust
    // validate threshold
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
        });
    }
```

**File:** src/frost/mod.rs (L120-159)
```rust
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
```
