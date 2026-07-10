### Title
Missing Validation of `old_signing_key` for New Participants in `assert_reshare_keys_invariants` Allows Silent Pre-flight Pass Followed by Reshare Failure - (File: src/dkg.rs)

### Summary

`assert_reshare_keys_invariants` in `src/dkg.rs` is the public pre-flight validation function callers invoke before executing a reshare. Its own inline comment at line 662 documents that it must check: *"if me is not in the old participant set then ensure that old_signing_key is None"*. The code that follows, however, implements only the **mirror** condition and leaves the documented check entirely absent. A new participant (one not present in the old participant set) who supplies a non-`None` `old_signing_key` passes validation without error, proceeds into `do_reshare`, and causes a `ProtocolError` deep inside the async execution path — after all other participants have already committed to the round.

---

### Finding Description

`assert_reshare_keys_invariants` is defined as:

```rust
// Step 1.1
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
``` [1](#0-0) 

The comment describes the guard that **should** exist:

```rust
// MISSING:
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(...));
}
```

The implemented guard catches only the opposite case (old participant, no share). The case described in the comment — new participant, non-`None` share — is never checked.

`ReconstructionLowerBound` is a plain newtype with no internal invariants: [2](#0-1) 

so no downstream type enforces the constraint either.

When `do_reshare` is subsequently called with these unchecked inputs, it computes:

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)          // ← me is NOT in intersection
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?
    ...
``` [3](#0-2) 

Because `me` is absent from `old_participants`, it is absent from `intersection`. `intersection.lagrange::<C>(me)` returns `Err(ProtocolError::InvalidIndex)`, which propagates via `?` and aborts the async future for that participant mid-protocol. [4](#0-3) 

---

### Impact Explanation

**Impact: High — Permanent denial of reshare for honest parties under valid protocol inputs.**

The pre-flight function `assert_reshare_keys_invariants` is the documented caller-facing guard. When it returns `Ok`, callers have no reason to suspect the subsequent `do_reshare` call will abort. The failure occurs asynchronously, after the protocol has started and other participants have already committed to their rounds. The affected participant's share is never updated to the new key. If the reshare cannot be retried (e.g., the old key material has been rotated or destroyed, or the triggering event is non-repeatable), that participant is permanently excluded from future signing quorums, constituting a permanent denial of reshare and downstream signing for an honest party.

---

### Likelihood Explanation

**Likelihood: Medium.**

The `assert_reshare_keys_invariants` function is the explicit pre-flight API. A new participant joining a reshare who mistakenly passes their old key share (e.g., from a prior epoch, or due to a copy-paste error in integration code) will receive a clean `Ok` from the validator and proceed. The comment in the source code itself documents the intended check, indicating the authors were aware of the case but the guard was never implemented. Any integration that calls `assert_reshare_keys_invariants` and trusts its result is exposed.

---

### Recommendation

Add the missing guard immediately after the existing check in `assert_reshare_keys_invariants`:

```rust
// if me is not in the old participant set then ensure that old_signing_key is None
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not present in the old participant list but provided a share"
    )));
}
```

This mirrors the existing check and closes the gap documented by the comment. Additionally, consider adding a test case that passes `old_signing_key = Some(...)` for a participant not in `old_participants` and asserts that `assert_reshare_keys_invariants` returns `Err`.

---

### Proof of Concept

1. Construct a reshare scenario with `old_participants = [P0, P1, P2]` and `new_participants = [P0, P1, P2, P3]`.
2. For participant `P3` (new joiner, not in old set), supply a non-`None` `old_signing_key`.
3. Call `assert_reshare_keys_invariants` for `P3` — it returns `Ok(...)` without error.
4. Call `do_reshare` for `P3` with the same arguments.
5. Inside `do_reshare`, `intersection = old_participants ∩ new_participants = {P0, P1, P2}`. `P3` is absent.
6. `intersection.lagrange::<C>(P3)` returns `Err(ProtocolError::InvalidIndex)`.
7. The `?` propagates the error; `P3`'s reshare future aborts.
8. `P3` retains its old (now stale) key share and cannot participate in future signing rounds using the new key. [5](#0-4) [6](#0-5)

### Citations

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

**File:** src/thresholds.rs (L9-12)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);
```

**File:** src/participants.rs (L135-140)
```rust
    pub fn index(&self, participant: Participant) -> Result<usize, ProtocolError> {
        self.indices
            .get(&participant)
            .copied()
            .ok_or(ProtocolError::InvalidIndex)
    }
```
