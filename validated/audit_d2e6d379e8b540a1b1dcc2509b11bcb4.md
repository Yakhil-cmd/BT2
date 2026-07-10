Looking at the external report's vulnerability class — **inconsistent handling of a special case across parallel branches** — I need to find a place in this codebase where one branch correctly guards a special case but a sibling branch omits the same guard.

Let me trace the `assert_reshare_keys_invariants` function in `src/dkg.rs`: [1](#0-0) 

The function validates two symmetric conditions:
- If `me` IS in old participants → `old_signing_key` must be `Some` (checked)
- If `me` is NOT in old participants → `old_signing_key` must be `None` (NOT checked)

The comment on line 662 even describes the missing check verbatim: *"if me is not in the old participant set then ensure that old_signing_key is None"* — but the code implements the opposite condition.

Compare with `assert_keyshare_inputs` (the internal function called later), which correctly handles both branches symmetrically: [2](#0-1) 

And the public `reshare` API that calls `assert_reshare_keys_invariants` before launching the protocol: [3](#0-2) 

---

### Title
Missing Symmetric Validation in `assert_reshare_keys_invariants` Allows New Participant to Supply Spurious `old_signing_key`, Causing Reshare Protocol Denial - (`src/dkg.rs`)

### Summary
`assert_reshare_keys_invariants` validates that an old participant must supply `old_signing_key`, but omits the symmetric check that a *new* participant (not in old participants) must supply `None`. A malicious new participant can pass `old_signing_key = Some(x)` through the public `reshare` API without triggering an `InitializationError`. The protocol is launched, computes a corrupted non-zero secret, and then aborts inside `do_keyshare` before the participant broadcasts anything — causing all honest participants to stall waiting for a message that never arrives.

### Finding Description

In `src/dkg.rs`, `assert_reshare_keys_invariants` enforces only one side of a two-sided invariant:

```rust
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {   // ← only one branch
    return Err(InitializationError::BadParameters(...));
}
// MISSING: if !old_participants.contains(me) && old_signing_key.is_some() { return Err(...) }
```

The comment on line 662 literally describes the missing check, but the code implements only the complementary case.

**Attack path:**

1. Malicious participant `M` is in `new_participants` but NOT in `old_participants`.
2. `M` calls `reshare(old_participants, old_threshold, Some(fake_key), old_pk, new_participants, new_threshold, M, rng)`.
3. `assert_reshare_keys_invariants` passes — the missing branch is never checked.
4. `reshare` returns `Ok(protocol)` with no error.
5. Inside `do_reshare` (line 613–620), `intersection.lagrange::<C>(M)` is called. Since `M` is not in the intersection, a non-trivial Lagrange coefficient `λ` is computed, yielding `secret = λ * fake_key ≠ 0`.
6. `do_keyshare` calls `assert_keyshare_inputs` (line 354–355), which detects `!is_zero_secret && !old_participants.contains(M)` and returns `ProtocolError::AssertionFailed` — **before any broadcast**.
7. `M`'s protocol terminates silently. All honest participants are blocked in `do_broadcast` waiting for `M`'s session-ID message that never arrives.
8. The reshare fails permanently for all honest parties.

The internal guard in `assert_keyshare_inputs` (lines 41–44) does catch this, but only after the protocol has already been launched and honest parties have committed to waiting. [4](#0-3) [5](#0-4) [6](#0-5) 

### Impact Explanation

**High — Permanent denial of resharing for honest parties.**

A malicious participant who is legitimately in the new participant set but not in the old set can repeatedly call `reshare` with a non-`None` `old_signing_key`. Each attempt causes the reshare round to stall: honest participants enter the broadcast wait loop and never receive `M`'s message. The reshare cannot complete. Because `assert_reshare_keys_invariants` is the only pre-launch gate, this is repeatable with zero cost to the attacker.

### Likelihood Explanation

Any participant in the new set who was not in the old set (a common scenario — adding new nodes during reshare) can trigger this. No privileged access, leaked keys, or cryptographic breaks are required. The attacker only needs to pass a non-`None` value for `old_signing_key` in the public `reshare` API.

### Recommendation

Add the symmetric check to `assert_reshare_keys_invariants`:

```rust
// Existing check: old participant must provide their share
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}

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

**File:** src/dkg.rs (L353-355)
```rust
    // Make sure you do not call do_keyshare with zero as secret on an old participant
    let (old_verification_key, old_participants) =
        assert_keyshare_inputs(me, &secret, old_reshare_package)?;
```

**File:** src/dkg.rs (L361-363)
```rust
    // Step 1.3 & 2.1
    let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;

```

**File:** src/dkg.rs (L637-668)
```rust
// Step 1.1
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
