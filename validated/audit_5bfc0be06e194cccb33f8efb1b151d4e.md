### Title
Missing Validation of `old_signing_key` for New Participants Causes Permanent Reshare DoS - (File: src/dkg.rs)

### Summary

`assert_reshare_keys_invariants` in `src/dkg.rs` fails to validate that a participant **not** present in the old participant set must supply `old_signing_key = None`. A malicious new joiner can pass `old_signing_key = Some(share)`, bypass the guard, and cause `do_keyshare` to abort before transmitting a single message. Every honest participant then blocks indefinitely waiting for that participant's Round-1 broadcast, permanently denying the reshare.

---

### Finding Description

`assert_reshare_keys_invariants` enforces only one direction of the key/membership invariant:

```rust
// src/dkg.rs  lines 662-667
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
```

The comment explicitly states the dual obligation — *"if me is **not** in the old participant set then ensure that `old_signing_key` is None"* — but the code never enforces it. The symmetric guard is absent:

```rust
// MISSING:
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(...));
}
```

Because the check is absent, a new participant (`me ∉ old_participants`) can supply `old_signing_key = Some(x_i)` and pass validation. Execution then enters `do_reshare`:

```rust
// src/dkg.rs  lines 611-620
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)          // me ∉ intersection, but succeeds mathematically
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?
    .unwrap_or_else(<C::Group as Group>::Field::zero);
```

`intersection.lagrange::<C>(me)` does **not** require `me` to be a member of the list; it computes a well-defined (but semantically wrong) Lagrange coefficient, returning a non-zero scalar. The non-zero `secret` is then forwarded to `do_keyshare` together with `old_reshare_package = Some((old_public_key, old_participants))`.

Inside `do_keyshare`, `assert_keyshare_inputs` catches the contradiction:

```rust
// src/dkg.rs  lines 39-44
} else {
    // return error if me is part of the old participants set
    if !old_participants.contains(me) {
        return Err(ProtocolError::AssertionFailed(
            format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
    }
}
```

This error fires **before** the first `do_broadcast` call (line 362), so the participant never sends its Round-1 session-ID message. Every other honest participant is blocked inside `do_broadcast` waiting for that message, with no timeout mechanism in the library.

---

### Impact Explanation

**High — Permanent denial of reshare for honest parties.**

All honest participants call `do_broadcast` in Round 1 and wait for a message from every member of `participants`. Because the malicious new joiner aborts before transmitting anything, the wait never completes. The reshare is permanently stalled; no new key shares are produced. This matches the allowed impact: *"Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions."*

---

### Likelihood Explanation

**High.** The public `reshare` entry-point accepts `old_signing_key: Option<SigningShare<C>>` from the caller. Any participant that is new to the group (not in `old_participants`) can trivially supply a fabricated `Some(share)`. The validation function explicitly documents the invariant in a comment but does not enforce it, so no additional capability beyond calling the public API is required.

---

### Recommendation

Add the symmetric guard immediately after the existing check in `assert_reshare_keys_invariants`:

```rust
// Existing check (lines 662-667)
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}

// ADD: symmetric guard
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not present in the old participant list but provided a share"
    )));
}
```

This ensures `do_reshare` is never called with a non-zero secret for a participant that is not a member of the old set, eliminating the pre-message abort path.

---

### Proof of Concept

```
Participants (old): [P1, P2, P3]   threshold = 2
Participants (new): [P2, P3, P4]   threshold = 2

P4 is a new joiner (P4 ∉ old_participants).
P4 calls reshare(..., old_signing_key = Some(fabricated_share), ...).

1. assert_reshare_keys_invariants:
   - assert_key_invariants passes (P4 ∈ new participants).
   - intersection check: |{P2,P3}| = 2 >= old_threshold = 2 → passes.
   - old_participants.contains(P4) == false → the existing guard is NOT triggered.
   → Validation returns Ok.

2. do_reshare:
   - intersection = {P2, P3}
   - intersection.lagrange::<C>(P4) → succeeds (P4 ∉ intersection but
     computation is mathematically valid), returns non-zero λ.
   - secret = λ * fabricated_share.to_scalar()  (non-zero)

3. do_keyshare(secret ≠ 0, old_reshare_package = Some((..., [P1,P2,P3]))):
   - assert_keyshare_inputs: secret ≠ 0 AND P4 ∉ old_participants
     → ProtocolError::AssertionFailed  (before any send)

4. P1, P2, P3 are blocked in do_broadcast Round 1 waiting for P4's
   session-ID message that never arrives → permanent hang.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/dkg.rs (L23-55)
```rust
fn assert_keyshare_inputs<C: Ciphersuite>(
    me: Participant,
    secret: &Scalar<C>,
    old_reshare_package: Option<(VerifyingKey<C>, ParticipantList)>,
) -> Result<(Option<VerifyingKey<C>>, Option<ParticipantList>), ProtocolError> {
    let is_zero_secret = *secret == <C::Group as Group>::Field::zero();

    if let Some((old_key, old_participants)) = old_reshare_package {
        if is_zero_secret {
            //  return error if me is not a purely new joiner to the participants set
            //  prevents accidentally calling keyshare with extremely old keyshares
            //  that have nothing to do with the current resharing
            if old_participants.contains(me) {
                return Err(ProtocolError::AssertionFailed(
                    format!("{me:?} is running Resharing with a zero share but does belong to the old participant set")));
            }
        } else {
            //  return error if me is part of the old participants set
            if !old_participants.contains(me) {
                return Err(ProtocolError::AssertionFailed(
                    format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
            }
        }
        Ok((Some(old_key), Some(old_participants)))
    } else {
        if is_zero_secret {
            return Err(ProtocolError::AssertionFailed(format!(
                "{me:?} is running DKG with a zero share"
            )));
        }
        Ok((None, None))
    }
}
```

**File:** src/dkg.rs (L357-362)
```rust
    // Start Round 1
    // Step 1.2
    let mut my_session_id = [0u8; 32]; // 256 bits
    rng.fill_bytes(&mut my_session_id);
    // Step 1.3 & 2.1
    let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;
```

**File:** src/dkg.rs (L600-635)
```rust
pub async fn do_reshare<C: Ciphersuite>(
    chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    old_participants: ParticipantList,
    mut rng: impl CryptoRngCore,
) -> Result<KeygenOutput<C>, ProtocolError> {
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

    let old_reshare_package = Some((old_public_key, old_participants));
    let keygen_output = do_keyshare::<C>(
        chan,
        participants,
        me,
        threshold,
        secret,
        old_reshare_package,
        &mut rng,
    )
    .await?;

    Ok(keygen_output)
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
