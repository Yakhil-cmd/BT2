### Title
Missing Inverse Validation in `assert_reshare_keys_invariants` Allows New Participant to Provide Stale Key Share, Permanently Blocking Honest Reshare Participants - (File: src/dkg.rs)

---

### Summary

`assert_reshare_keys_invariants` enforces only one direction of the key-presence invariant: it rejects an old participant who omits their share, but it never rejects a **new** participant (not in `old_participants`) who **supplies** a share. When a new joiner passes a non-`None` `old_signing_key`, initialization succeeds, but the async protocol body aborts before sending any Round-1 message. Every other honest participant blocks indefinitely waiting for that participant's session-ID broadcast, permanently denying the reshare.

---

### Finding Description

`assert_reshare_keys_invariants` (`src/dkg.rs:637-669`) contains only one half of the required symmetry check:

```rust
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
``` [1](#0-0) 

The comment itself describes the missing check ("if me is **not** in the old participant set then ensure that `old_signing_key` is `None`"), but the code only implements the opposite guard. The inverse condition — `me` **not** in `old_participants` AND `old_signing_key = Some(...)` — is never rejected here.

Because `assert_reshare_keys_invariants` passes, the public `reshare()` entry-point returns `Ok(protocol)` without error: [2](#0-1) 

When the protocol is subsequently driven, `do_reshare` attempts to compute the Lagrange coefficient for `me` over the intersection of old and new participants:

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?
    .unwrap_or_else(<C::Group as Group>::Field::zero);
``` [3](#0-2) 

Because `me` is absent from `old_participants`, it is absent from `intersection`. `intersection.lagrange::<C>(me)` returns an error; `transpose()?` propagates it as a `ProtocolError`, and `do_reshare` returns before sending **any** network message — specifically before the Round-1 session-ID broadcast issued by `do_broadcast`: [4](#0-3) 

All other honest participants have already entered the protocol and are blocked in `do_broadcast` waiting for `me`'s session-ID. No timeout is present in the broadcast loop, so they wait indefinitely.

The secondary guard inside `assert_keyshare_inputs` (`src/dkg.rs:41-44`) that would catch a non-zero secret for a non-old participant is never reached because `do_reshare` aborts earlier. [5](#0-4) 

---

### Impact Explanation

**High — Permanent denial of reshare for honest parties.**

A new joiner who supplies a non-`None` `old_signing_key` (accidentally, e.g. by reusing a stale `KeygenOutput`, or deliberately) causes the reshare to abort for themselves before any Round-1 message is sent. Every other honest participant is left permanently blocked waiting for the missing broadcast. Because the library exposes no timeout on the broadcast wait, the reshare session is unrecoverable without external intervention, matching the allowed impact: *"Permanent denial of… reshare… for honest parties under valid protocol inputs and documented trust assumptions."*

---

### Likelihood Explanation

Moderate. The `reshare()` API accepts `old_signing_key: Option<SigningShare<C>>` as a plain caller-supplied argument. A new participant joining an existing group could easily pass a stale share from a prior session (e.g., after a key rotation). A malicious participant who is a new joiner can deliberately trigger this to abort any reshare session they are invited to. The missing `InitializationError` means the caller receives `Ok(protocol)` and has no indication of the problem until the protocol hangs.

---

### Recommendation

Add the inverse guard immediately after the existing check in `assert_reshare_keys_invariants`:

```rust
// Existing check
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
// Missing inverse check
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not in the old participant list but provided a share"
    )));
}
``` [6](#0-5) 

This makes the invariant symmetric, catches the invalid input at `InitializationError` time (before the protocol is created), and prevents the async abort that leaves honest participants blocked.

---

### Proof of Concept

1. Run keygen with `participants = [P1, P2, P3]`, `threshold = 2`. All three receive valid `KeygenOutput`.
2. Initiate reshare: `old_participants = [P1, P2, P3]`, `new_participants = [P1, P2, P3, P4]`, `old_threshold = 2`, `new_threshold = 2`.
3. P4 (new joiner, not in `old_participants`) calls `reshare()` with `old_signing_key = Some(stale_share)` instead of `None`.
4. `assert_reshare_keys_invariants` passes — the missing check does not fire.
5. `reshare()` returns `Ok(protocol)` with no error.
6. All four participants drive their protocols. P1, P2, P3 enter `do_broadcast` and wait for P4's session-ID.
7. P4's `do_reshare` immediately hits `intersection.lagrange::<C>(P4)` → error → `ProtocolError` → P4 never sends its Round-1 message.
8. P1, P2, P3 block indefinitely in `do_broadcast` waiting for P4's session-ID broadcast, permanently denying the reshare. [7](#0-6) [8](#0-7)

### Citations

**File:** src/dkg.rs (L39-44)
```rust
        } else {
            //  return error if me is part of the old participants set
            if !old_participants.contains(me) {
                return Err(ProtocolError::AssertionFailed(
                    format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
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

**File:** src/lib.rs (L120-141)
```rust
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
