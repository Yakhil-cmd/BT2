### Title
Missing Lower-Bound Validation on `ReconstructionLowerBound` in FROST Signing Functions Allows Threshold-0/1 Signing — (`src/frost/mod.rs`)

---

### Summary

`ReconstructionLowerBound` is an unconstrained `usize` wrapper that accepts 0. The FROST signing entry-points `assert_sign_inputs` and `presign` in `src/frost/mod.rs` only validate the **upper** bound (`threshold <= participants.len()`) but never enforce a **lower** bound (`threshold >= 2`), even though the DKG layer enforces `threshold >= 2` via `ThresholdTooSmall`. A malicious coordinator or library caller can invoke signing with `threshold = 0` or `threshold = 1`, causing the signing protocol to proceed with fewer participants than the security threshold established at key-generation time, producing an unusable or cryptographically incorrect signature output.

---

### Finding Description

`ReconstructionLowerBound` is defined as a plain `usize` newtype with no constructor-level validation: [1](#0-0) 

Any `usize` value — including 0 — is accepted via the `From<usize>` derive.

The DKG entry-point (`keygen`) correctly rejects `threshold < 2` with `InitializationError::ThresholdTooSmall { min: 2 }`: [2](#0-1) 

However, the FROST signing helper `assert_sign_inputs` — which is the shared validation gate for EdDSA and RedJubjub signing — only checks the upper bound: [3](#0-2) 

There is **no** corresponding lower-bound check. `threshold = 0` and `threshold = 1` both pass this guard silently.

The same omission exists in the FROST `presign` function: [4](#0-3) 

The OT-based ECDSA `sign` function has the same pattern — it checks `participants.len() < threshold` but never checks `threshold >= 2`: [5](#0-4) 

By contrast, the triple-generation path (`validate_triple_inputs`) **does** enforce the lower bound correctly: [6](#0-5) 

This inconsistency means the threshold invariant is enforced at key-generation and triple-generation time but is silently dropped at signing time.

---

### Impact Explanation

In FROST, the `threshold` value passed to signing controls how many signature shares the coordinator collects and how Lagrange interpolation is performed during aggregation. If the DKG was run with `threshold = 2` (degree-1 polynomial), but signing is invoked with `threshold = 1`, the coordinator aggregates only one participant's share using a trivial Lagrange coefficient of 1. The resulting aggregate scalar does **not** equal the correct group secret, so the produced signature is cryptographically invalid and will fail verification against the established public key. Honest participants believe they have completed a signing session, but the output is unusable — constituting **corruption of signing output** (honest parties accept an unusable cryptographic output).

If `threshold = 0` is passed, the coordinator may aggregate zero shares, producing a zero/identity scalar, which is an even more degenerate corrupt output.

**Mapped impact:** High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.

---

### Likelihood Explanation

The `threshold` parameter is supplied by the **caller** at signing time and is not cryptographically bound to the `KeygenOutput`. A malicious coordinator controlling the signing session setup can freely pass `threshold = 1` (or 0) to `assert_sign_inputs` / `presign`. No special privilege or key material is required — only the ability to initiate a signing session, which is the normal role of a coordinator. The attack is straightforward and requires no cryptographic capability.

---

### Recommendation

Add a lower-bound check in `assert_sign_inputs` and in the FROST `presign` function, mirroring the check already present in `validate_triple_inputs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Additionally, consider adding a constructor `ReconstructionLowerBound::new(v: usize) -> Result<Self, InitializationError>` that enforces `v >= 2` at the type level, so the invariant cannot be violated by future callers.

---

### Proof of Concept

```rust
// DKG run with threshold = 2 (minimum enforced by keygen)
let keygen_out = run_keygen(&participants, 2, &mut rng);

// Malicious coordinator invokes FROST signing with threshold = 1
// assert_sign_inputs accepts this — only checks threshold <= participants.len()
let signing_participants = frost::assert_sign_inputs(
    &participants,
    1usize,          // threshold = 1, below DKG threshold of 2
    me,
    coordinator,
).unwrap(); // succeeds — no lower-bound check

// Presign also accepts threshold = 1
let presign_args = frost::PresignArguments {
    keygen_out: keygen_out[0].1.clone(),
    threshold: ReconstructionLowerBound::from(1usize), // accepted, no validation
};
let _ = frost::presign(&participants, me, &presign_args, rng).unwrap();

// Signing proceeds with 1 share; Lagrange interpolation over 1 point
// produces a scalar that does not equal the group secret.
// The resulting signature fails verification against the public key —
// honest parties have accepted a corrupt, unusable signing output.
``` [7](#0-6) [8](#0-7)

### Citations

**File:** src/thresholds.rs (L1-25)
```rust
use derive_more::{From, Into};
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct MaxMalicious(usize);

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);

// ----- MaxMalicious conversions -----
impl MaxMalicious {
    pub fn value(self) -> usize {
        self.0
    }
}

impl ReconstructionLowerBound {
    pub fn value(self) -> usize {
        self.0
    }
}
```

**File:** src/dkg.rs (L738-756)
```rust
    pub fn keygen__should_fail_if_threshold_is_below_limit<
        C: Ciphersuite,
        R: CryptoRngCore + SeedableRng + Send + 'static,
    >(
        rng: &mut R,
    ) where
        <C::Group as Group>::Element: std::fmt::Debug + std::marker::Send,
        <<C::Group as Group>::Field as Field>::Scalar: std::marker::Send,
    {
        let threshold = 1;
        let participants = generate_participants(2);

        let rng_keygen = R::seed_from_u64(rng.next_u64());
        let result = keygen::<C>(&participants, participants[0], threshold, rng_keygen);

        assert_eq!(
            result.err().unwrap(),
            InitializationError::ThresholdTooSmall { threshold, min: 2 }
        );
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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L57-63)
```rust
    // ensure number of participants during the signing phase is >= threshold
    if participants.len() < threshold {
        return Err(InitializationError::NotEnoughParticipantsForThreshold {
            threshold,
            participants: participants.len(),
        });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-704)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
```
