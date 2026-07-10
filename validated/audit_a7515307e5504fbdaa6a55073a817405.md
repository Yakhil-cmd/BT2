### Title
Missing Lower-Bound Validation on `threshold` in FROST `assert_sign_inputs` Allows Corrupted Signing Output — (`src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` validates only the upper bound of the `threshold` parameter (`threshold > participants.len()`), but omits the lower-bound check (`threshold >= 2`) that every other initialization guard in the codebase enforces. A malicious coordinator or misconfigured caller can supply `threshold = 1` to FROST signing. Under standard FROST behavior, the coordinator collects only `threshold` partial signatures; with `threshold = 1`, a single participant's raw key share is used as the Lagrange interpolant, producing an invalid aggregate signature that cannot be verified against the group public key.

---

### Finding Description

Every other threshold-validation helper in the codebase enforces a minimum of 2:

`assert_key_invariants` in `src/dkg.rs`: [1](#0-0) 

`validate_triple_inputs` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs`: [2](#0-1) 

`assert_sign_inputs` in `src/frost/mod.rs` is the sole exception. It checks only the upper bound:

```rust
// src/frost/mod.rs lines 144-150
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
``` [3](#0-2) 

There is no corresponding guard:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

The `participants.len() < 2` guard at line 127 does not compensate for this, because it is possible to have `participants.len() >= 2` and `threshold = 1` simultaneously — both checks pass. [4](#0-3) 

The `ReconstructionLowerBound` type is a plain wrapper with no self-enforced minimum; the DKG test at `src/dkg.rs` line 747 explicitly constructs `threshold = 1` to demonstrate that the type itself permits it, relying on the caller-side guard to reject it. [5](#0-4) 

---

### Impact Explanation

In FROST, the coordinator selects exactly `threshold` participants whose partial signatures are aggregated. With `threshold = 1`, only one participant's partial signature `z_i = r_i + λ_i · x_i · c` is used. Because there is only one interpolation point, the Lagrange coefficient `λ_i = 1`, so the partial signature reduces to `z_i = r_i + x_i · c`, where `x_i` is participant `i`'s key *share*, not the reconstructed group secret `x`.

The aggregate signature `(R_i, z_i)` fails verification against the group public key `X = x · G` because `z_i · G = R_i + c · X_i ≠ R + c · X` (since `x_i ≠ x` for any keygen with `threshold ≥ 2`). Honest parties receive a cryptographically unusable output.

**Matched impact**: *High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.*

---

### Likelihood Explanation

`assert_sign_inputs` is a public library entry point called directly by callers of the FROST EdDSA and RedJubjub signing APIs. The threshold is a caller-supplied parameter with no cross-validation against the keygen output stored in `KeygenOutput`. A malicious coordinator, or any caller that accidentally passes `threshold = 1` (e.g., off-by-one when converting from a 0-indexed count), reaches this path without any other guard catching it. The DKG enforces `threshold ≥ 2`, but the signing layer does not inherit or re-check that invariant.

---

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` and `validate_triple_inputs` already use:

```rust
// src/frost/mod.rs — inside assert_sign_inputs, after the upper-bound check
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing pattern: [1](#0-0) 

---

### Proof of Concept

1. Run DKG for participants `[A, B, C]` with `threshold = 2`. Each party receives a key share `x_i` of the group secret `x`.
2. Call the FROST signing API with `participants = [A, B]` and `threshold = 1`. `assert_sign_inputs` passes: `1 ≤ 2` (upper bound) and `2 ≥ 2` (participant count).
3. The coordinator collects only participant A's partial signature: `z_A = r_A + 1 · x_A · c`.
4. The aggregate signature `(R_A, z_A)` is returned to callers.
5. Verification: `z_A · G = R_A + c · X_A`, but the expected equation is `z · G = R + c · X`. Since `X_A ≠ X`, verification fails — the signing output is corrupted and unusable. [6](#0-5)

### Citations

**File:** src/dkg.rs (L580-582)
```rust
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/dkg.rs (L747-755)
```rust
        let threshold = 1;
        let participants = generate_participants(2);

        let rng_keygen = R::seed_from_u64(rng.next_u64());
        let result = keygen::<C>(&participants, participants[0], threshold, rng_keygen);

        assert_eq!(
            result.err().unwrap(),
            InitializationError::ThresholdTooSmall { threshold, min: 2 }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-703)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
```

**File:** src/frost/mod.rs (L120-160)
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
}
```
