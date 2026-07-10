### Title
Missing Lower-Bound Threshold Validation in `assert_sign_inputs` Allows Signing with Degenerate Threshold — (File: src/frost/mod.rs)

---

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` validates signing inputs for EdDSA/FROST but omits a lower-bound check on the `threshold` parameter. Unlike `assert_key_invariants` in `src/dkg.rs`, which enforces `threshold >= 2`, `assert_sign_inputs` only checks that `threshold <= participants.len()`. A caller supplying `threshold = 0` or `threshold = 1` passes validation, and the signing protocol proceeds with degenerate Lagrange interpolation, producing an unusable or cryptographically incorrect signature.

---

### Finding Description

`assert_key_invariants` (the DKG entry-point validator) enforces a strict lower bound:

```rust
// src/dkg.rs lines 580-582
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`assert_sign_inputs` (the signing entry-point validator) performs **only** an upper-bound check:

```rust
// src/frost/mod.rs lines 144-150
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
``` [2](#0-1) 

There is no corresponding `threshold < 2` guard. The same omission exists in `presign`:

```rust
// src/frost/mod.rs lines 71-77
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` newtype with no type-level minimum enforcement:

```rust
// src/thresholds.rs lines 9-12
pub struct ReconstructionLowerBound(usize);
``` [4](#0-3) 

Any caller — including a malicious coordinator or a misconfigured honest party — can construct `ReconstructionLowerBound(0)` or `ReconstructionLowerBound(1)` and pass it to `assert_sign_inputs`. The function returns `Ok(participants)`, and the signing protocol proceeds.

The analogy to the external report is direct:

| External Report | This Codebase |
|---|---|
| Missing `fillAmount > 0` check | Missing `threshold >= 2` check |
| Zero fill → default market struct read | Zero/one threshold → degenerate Lagrange basis |
| Default `RewardStyle.Upfront == 0` → unintended transfer | Degenerate interpolation → invalid/unusable signature |

---

### Impact Explanation

FROST signing uses Lagrange interpolation to combine per-participant signature shares. The threshold determines the degree of the polynomial and the set of Lagrange coefficients. When `threshold = 1`, only one participant's share is combined with a trivial coefficient, producing a scalar that does not correspond to the secret key shared at the correct threshold. When `threshold = 0`, `threshold - 1` underflows (wraps to `usize::MAX` in release builds), causing the commitment-length check inside `verify_proof_of_knowledge` to compare against `usize::MAX`, which silently passes or panics depending on build mode. [5](#0-4) 

In both cases, honest participants executing the signing protocol with a caller-supplied degenerate threshold will produce a signature that fails external verification. This matches:

> **High: Corruption of sign outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

---

### Likelihood Explanation

`assert_sign_inputs` is a public API function. Its `threshold` argument is caller-supplied with no type-level minimum. A malicious coordinator, a misconfigured integration, or a participant replaying an old threshold value from a prior key epoch can trivially supply `threshold = 0` or `threshold = 1`. No privileged access or cryptographic break is required.

---

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` already enforces, immediately after the upper-bound check in `assert_sign_inputs`:

```rust
// src/frost/mod.rs — inside assert_sign_inputs
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Apply the identical guard inside `presign` after the `args.threshold.value() > participants.len()` check.

---

### Proof of Concept

1. A caller constructs `ReconstructionLowerBound(1)` (valid Rust, no compile error).
2. Calls `assert_sign_inputs(&[A, B], ReconstructionLowerBound(1), A, B)`.
3. Check `1 > 2` → false → no error returned; function returns `Ok(participants)`.
4. The EdDSA/RedJubjub signing protocol proceeds with `threshold = 1`.
5. Lagrange interpolation combines only one participant's share with coefficient 1, ignoring the second participant's share entirely.
6. The resulting signature scalar does not reconstruct the correct aggregate secret, and the signature fails verification against the public key produced during DKG (which used `threshold >= 2`).
7. All honest parties have wasted a presignature and produced an unusable output; the signing session must be aborted and restarted. [6](#0-5) [7](#0-6)

### Citations

**File:** src/dkg.rs (L191-193)
```rust
            if commitment.coefficients().len() != threshold - 1 {
                return Err(ProtocolError::IncorrectNumberOfCommitments);
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

**File:** src/thresholds.rs (L9-12)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);
```
