### Title
Missing Lower-Bound Threshold Validation in FROST Signing Allows Signing with Degenerate Threshold - (File: src/frost/mod.rs)

### Summary
`assert_sign_inputs` in `src/frost/mod.rs` validates only the upper bound of the threshold parameter (`threshold > participants.len()`) but omits the lower-bound check (`threshold < 2`) that is explicitly enforced in `assert_key_invariants` in `src/dkg.rs`. A caller passing `threshold = 1` (or `0`) to any FROST signing entry point bypasses this guard, causing the signing protocol to proceed with a degenerate polynomial, producing an unusable or inconsistent signature output for all honest participants.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on the threshold:

```rust
// src/dkg.rs lines 573–582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs` enforces only the upper bound:

```rust
// src/frost/mod.rs lines 144–150
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← lower-bound check (threshold < 2) is absent
``` [2](#0-1) 

`assert_sign_inputs` is the sole validation gate called by both FROST signing entry points confirmed by grep: `src/frost/eddsa/sign.rs` and `src/frost/redjubjub/sign.rs`. [3](#0-2) 

The structural parallel to the reported bug is exact: the keygen path checks the full valid range (`2 ≤ threshold ≤ n`), while the signing path checks only one side of the range (`threshold ≤ n`), leaving the lower boundary unguarded — analogous to checking `stakerIndex == 99` instead of `stakerIndex <= 99`.

### Impact Explanation

FROST signing uses Lagrange interpolation over `threshold` shares to reconstruct the group nonce contribution. With `threshold = 1` the polynomial is degree-0 (a constant), meaning a single participant's share alone determines the output. The resulting partial signatures are computed against a degree-0 commitment polynomial that is inconsistent with the degree-`(t-1)` polynomial committed to during DKG (which enforced `t ≥ 2`). Every honest participant will either produce a signature that fails standard FROST verification against the master public key, or the aggregation step will produce an output that is cryptographically inconsistent with the established key material. All honest parties accept an unusable signing output.

This maps to: **High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation

`assert_sign_inputs` is a public API validation function. Any library consumer — including an application developer integrating FROST signing or a coordinator constructing signing sessions — can supply `threshold = 1` (or `0`). No special privilege or key compromise is required. The missing check is a single missing `if` branch; the path is directly reachable on the first call to either FROST signing entry point.

### Recommendation

Add the lower-bound check to `assert_sign_inputs` in `src/frost/mod.rs`, mirroring `assert_key_invariants`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
``` [4](#0-3) 

### Proof of Concept

1. Generate FROST keys with `threshold = 2`, `n = 3` participants (valid; `assert_key_invariants` enforces `threshold ≥ 2`).
2. Call the FROST EdDSA or RedJubjub `sign` entry point with the same participants but pass `threshold = 1`.
3. `assert_sign_inputs` passes: `1 > 3` is false (no `ThresholdTooLarge`), and the missing lower-bound check means `ThresholdTooSmall` is never raised.
4. The signing protocol proceeds with a degree-0 polynomial. Lagrange interpolation uses a single share, producing partial signatures inconsistent with the degree-1 commitment polynomial established during DKG.
5. The aggregated signature fails verification against the master public key; all honest participants have accepted an unusable output. [3](#0-2) [5](#0-4)

### Citations

**File:** src/dkg.rs (L558-596)
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

    // ensure uniqueness of participants in the participant list
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
    Ok(participants)
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
