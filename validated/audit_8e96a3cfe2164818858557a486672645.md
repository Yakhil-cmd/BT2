### Title
Missing `old_threshold` Lower-Bound Validation in `assert_reshare_keys_invariants` Causes `do_reshare` to Fail with `InvalidInterpolationArguments` - (File: src/dkg.rs)

---

### Summary

`assert_reshare_keys_invariants` validates the new threshold (`>= 2`) but never validates that `old_threshold >= 2`. A caller who passes `old_threshold = 1` will pass the intersection-size guard, receive an `Ok(protocol)` from `reshare()`, and then have the protocol abort inside `do_reshare` when `intersection.lagrange::<C>(me)` is called on a one-element set — exactly the same "accepted at setup, explodes at execution" pattern as the external report.

---

### Finding Description

`assert_reshare_keys_invariants` in `src/dkg.rs` enforces `threshold >= 2` for the **new** threshold via `assert_key_invariants`, but applies no analogous lower-bound check to `old_threshold`:

```rust
// src/dkg.rs  assert_reshare_keys_invariants
let threshold     = usize::from(threshold.into());
let old_threshold = usize::from(old_threshold.into());   // ← never checked >= 2

let participants = assert_key_invariants(participants, me, threshold)?; // new threshold ≥ 2 ✓

let old_participants =
    ParticipantList::new(old_participants)
        .ok_or(InitializationError::DuplicateParticipants)?;

// passes when old_threshold == 1 and intersection has exactly one member (me)
if old_participants.intersection(&participants).len() < old_threshold {
    return Err(InitializationError::NotEnoughParticipantsForNewThreshold { … });
}
```

Because the guard only requires `intersection.len() >= old_threshold`, setting `old_threshold = 1` lets the check pass with a single-element intersection. `reshare()` then returns `Ok(protocol)` and schedules `do_reshare`:

```rust
// src/dkg.rs  do_reshare
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)          // ← called on a 1-element list
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?                       // ← propagates the error
    .unwrap_or_else(…);
```

`ParticipantList::lagrange` delegates to `compute_lagrange_coefficient`, which immediately returns `Err(ProtocolError::InvalidInterpolationArguments)` when `points_set.len() <= 1`:

```rust
// src/crypto/polynomials.rs  compute_lagrange_coefficient
if points_set.len() <= 1 {
    return Err(ProtocolError::InvalidInterpolationArguments);
}
```

The error propagates through `transpose()?`, aborting `do_reshare` and therefore the entire reshare protocol for every honest participant who holds an old signing share.

---

### Impact Explanation

Every honest old participant who calls `reshare()` with `old_threshold = 1` and a one-element intersection will have their protocol instance abort at the Lagrange step. Because the protocol is multi-party, the remaining participants wait indefinitely for messages that will never arrive, causing a permanent stall of the reshare round. No new key shares are produced; the key set cannot be rotated until a fresh reshare is initiated with correct parameters.

This maps to **High: Permanent denial of reshare for honest parties under valid protocol inputs**, because the library accepts the parameters without error at initialization time, giving callers no indication that execution will fail.

---

### Likelihood Explanation

The `reshare` public API accepts `old_threshold` as an opaque `impl Into<ReconstructionLowerBound>`. The type carries no minimum-value invariant, and the library documents no lower bound for `old_threshold` in its public interface. A library integrator who is migrating from a 2-of-N scheme to a new participant set, and who mistakenly passes `1` as the old threshold (e.g., off-by-one, or copying a `MaxMalicious` value instead of a `ReconstructionLowerBound`), will trigger this path. A malicious coordinator who controls the reshare session parameters can also deliberately supply `old_threshold = 1` to abort the reshare for all old participants.

---

### Recommendation

Add an explicit lower-bound check for `old_threshold` in `assert_reshare_keys_invariants`, mirroring the check already present for the new threshold in `assert_key_invariants`:

```rust
if old_threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: old_threshold,
        min: 2,
    });
}
```

Place this check immediately after `old_threshold` is extracted from the `Into` conversion, before the intersection guard, so that callers receive a clear `InitializationError` rather than a cryptographic runtime failure.

---

### Proof of Concept

```
// Participants: old = [P0, P1], new = [P0, P2]
// old_threshold deliberately set to 1 (should be 2)

let old_participants = vec![P0, P1];
let new_participants = vec![P0, P2];
let old_threshold = 1usize;   // ← invalid, but not rejected
let new_threshold = 2usize;

// reshare() returns Ok(protocol) — no error at init time
let protocol = reshare::<C>(
    &old_participants,
    old_threshold,          // ← passes assert_reshare_keys_invariants
    Some(old_signing_key),  // P0 is an old participant
    old_public_key,
    &new_participants,
    new_threshold,
    P0,
    rng,
).unwrap();                 // succeeds

// When the protocol is driven to completion, do_reshare runs:
//   intersection = {P0}  (len == 1)
//   intersection.lagrange::<C>(P0)
//     → compute_lagrange_coefficient(&[P0_scalar], &P0_scalar, None)
//     → Err(ProtocolError::InvalidInterpolationArguments)   ← abort
//
// All participants stall; no new key shares are produced.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** src/dkg.rs (L610-620)
```rust
    let threshold = threshold.into();
    let intersection = old_participants.intersection(&participants);
    // either extract the share and linearize it or set it to zero
    let secret = old_signing_key
        .map(|x_i| {
            intersection
                .lagrange::<C>(me)
                .map(|lambda| lambda * x_i.to_scalar())
        })
        .transpose()?
        .unwrap_or_else(<C::Group as Group>::Field::zero);
```

**File:** src/dkg.rs (L638-668)
```rust
pub fn assert_reshare_keys_invariants<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    old_signing_key: Option<SigningShare<C>>,
    old_threshold: impl Into<ReconstructionLowerBound>,
    old_participants: &[Participant],
) -> Result<(ParticipantList, ParticipantList), InitializationError> {
    let threshold = usize::from(threshold.into());
    let old_threshold = usize::from(old_threshold.into());

    let participants = assert_key_invariants(participants, me, threshold)?;

    let old_participants =
        ParticipantList::new(old_participants).ok_or(InitializationError::DuplicateParticipants)?;

    // Step 1.1
    if old_participants.intersection(&participants).len() < old_threshold {
        return Err(InitializationError::NotEnoughParticipantsForNewThreshold {
            threshold: old_threshold,
            participants: old_participants.intersection(&participants).len(),
        });
    }
    // Step 1.1
    // if me is not in the old participant set then ensure that old_signing_key is None
    if old_participants.contains(me) && old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "party {me:?} is present in the old participant list but provided no share"
        )));
    }
    Ok((participants, old_participants))
```

**File:** src/participants.rs (L151-159)
```rust
    pub fn lagrange<C: Ciphersuite>(&self, p: Participant) -> Result<Scalar<C>, ProtocolError> {
        let p = p.scalar::<C>();
        let identifiers: Vec<Scalar<C>> = self
            .participants()
            .iter()
            .map(Participant::scalar::<C>)
            .collect();
        Ok(compute_lagrange_coefficient::<C>(&identifiers, &p, None)?.0)
    }
```

**File:** src/crypto/polynomials.rs (L410-413)
```rust
    if points_set.len() <= 1 {
        // returns error if there is not enough points to interpolate
        return Err(ProtocolError::InvalidInterpolationArguments);
    }
```
