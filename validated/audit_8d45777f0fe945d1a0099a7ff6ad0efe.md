### Title
Missing Validation of `old_threshold` and `old_participants` in `assert_reshare_keys_invariants` Allows Corrupted Reshare Outputs — (File: `src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` fully validates the **new** threshold and participant set via `assert_key_invariants`, but applies no equivalent sanity checks to `old_threshold` or `old_participants`. A caller (malicious participant or coordinator) can supply an `old_threshold` of `0` or `1`, trivially bypassing the intersection guard, and proceed into `do_reshare` with fewer contributing old participants than the actual security threshold requires. The resulting Lagrange interpolation is incorrect, producing new key shares that do not correspond to the original public key and causing the reshare to abort for all honest parties.

---

### Finding Description

`assert_key_invariants` (called for the new participant set) enforces three invariants: [1](#0-0) 

```
participants.len() >= 2
threshold >= 2
threshold <= participants.len()
```

`assert_reshare_keys_invariants` calls `assert_key_invariants` only for the **new** participants and threshold. For the **old** side it only deduplicates `old_participants` and then runs a single intersection check: [2](#0-1) 

```rust
let old_participants =
    ParticipantList::new(old_participants).ok_or(InitializationError::DuplicateParticipants)?;

if old_participants.intersection(&participants).len() < old_threshold {
    return Err(InitializationError::NotEnoughParticipantsForNewThreshold { … });
}
```

Neither `old_threshold >= 2` nor `old_threshold <= old_participants.len()` is ever checked. Because `old_threshold` is a `usize`, passing `old_threshold = 0` makes the guard `intersection.len() < 0` always `false` (unsigned comparison), so the check is silently skipped regardless of how many old participants are actually present in the new set.

Inside `do_reshare`, the linearised secret is computed over the intersection: [3](#0-2) 

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection.lagrange::<C>(me)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    …
```

If the intersection is smaller than the actual threshold (because `old_threshold` was set too low to enforce the correct minimum), the Lagrange coefficients are computed over an under-sized set. The resulting "linearised secret" is not the original secret, so the new public key diverges from the old one. The post-protocol check in `do_keyshare`: [4](#0-3) 

```rust
if old_vk != verifying_key {
    return Err(ProtocolError::AssertionFailed(
        "new public key does not match old public key".to_string(),
    ));
}
```

then aborts the protocol for every honest participant, leaving them with no usable new key shares.

---

### Impact Explanation

**High — Corruption of reshare outputs so honest parties accept unusable cryptographic outputs.**

When `old_threshold` is set below the actual threshold (e.g., `0` or `1`), the intersection guard is bypassed, the Lagrange interpolation is wrong, and the reshare protocol terminates with an assertion failure for all honest participants. No valid new key shares are produced; the group's signing capability is destroyed for that reshare session.

---

### Likelihood Explanation

**Medium.** The `reshare` public API accepts `old_threshold` as a plain caller-supplied value with no library-side bounds check. Any participant or coordinator that controls the call site can supply an out-of-range value — either maliciously (to grief the reshare) or accidentally (off-by-one, wrong variable). The new-threshold path has explicit guards; the absence of equivalent guards on the old-threshold path is a straightforward oversight that mirrors the DAO `maxMembers` pattern exactly.

---

### Recommendation

Apply the same three-invariant check to `old_threshold` and `old_participants` that `assert_key_invariants` applies to the new side:

```rust
// inside assert_reshare_keys_invariants, after building old_participants:
if old_participants.len() < 2 {
    return Err(InitializationError::NotEnoughParticipants {
        participants: old_participants.len(),
    });
}
if old_threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold: old_threshold, min: 2 });
}
if old_threshold > old_participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: old_threshold,
        max: old_participants.len(),
    });
}
```

This mirrors the existing validation path in `assert_key_invariants`: [5](#0-4) 

---

### Proof of Concept

```rust
// Pseudocode – each participant calls reshare() with old_threshold = 0
let result = reshare::<MyCiphersuite>(
    &old_participants,   // e.g. [P1, P2, P3], actual threshold was 3
    0usize,             // old_threshold = 0  ← bypasses intersection guard
    Some(my_old_share),
    old_public_key,
    &new_participants,
    3usize,
    me,
    rng,
);
// assert_reshare_keys_invariants passes (0 < 0 is false for usize)
// do_reshare runs with intersection.len() potentially < 3
// Lagrange interpolation is wrong → new_vk ≠ old_vk
// do_keyshare returns AssertionFailed for every honest participant
// → reshare is permanently corrupted for this session
```

### Citations

**File:** src/dkg.rs (L489-496)
```rust
    if let Some(old_vk) = old_verification_key {
        // check the equality between the old key and the new key without failing the unwrap
        if old_vk != verifying_key {
            return Err(ProtocolError::AssertionFailed(
                "new public key does not match old public key".to_string(),
            ));
        }
    }
```

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

**File:** src/dkg.rs (L638-669)
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
}
```

**File:** src/lib.rs (L106-141)
```rust
pub fn reshare<C: Ciphersuite>(
    old_participants: &[Participant],
    old_threshold: impl Into<ReconstructionLowerBound> + Send + 'static,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    new_participants: &[Participant],
    new_threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::new();
    let threshold = new_threshold;
    let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        old_threshold,
        old_participants,
    )?;
    let fut = do_reshare(
        comms.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
        rng,
    );
    Ok(make_protocol(comms, fut))
}
```
