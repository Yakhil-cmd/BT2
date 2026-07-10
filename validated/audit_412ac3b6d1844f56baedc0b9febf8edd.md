### Title
Missing Inverse Participant-Key Validation in `assert_reshare_keys_invariants` Allows Permanent Denial of Reshare — (File: `src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` validates only one direction of the participant/key invariant: it rejects an old participant who provides no signing key. It does **not** reject a new participant (one absent from `old_participants`) who provides a non-`None` `old_signing_key`. This asymmetric guard allows a caller to successfully construct a `reshare` protocol object that immediately fails inside the async future before sending any messages, permanently blocking all honest participants who are waiting for that node's broadcast contribution.

---

### Finding Description

In `src/dkg.rs`, `assert_reshare_keys_invariants` enforces only one side of the invariant:

```rust
// src/dkg.rs:662-667
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
``` [1](#0-0) 

The symmetric case — `me` is **not** in `old_participants` but `old_signing_key` is `Some(...)` — is never checked. The function returns `Ok(...)` for this invalid combination. [2](#0-1) 

When `reshare()` in `src/lib.rs` is called with this invalid combination, it passes `assert_reshare_keys_invariants` and returns a valid `Protocol` object: [3](#0-2) 

Inside `do_reshare`, the Lagrange coefficient for `me` is computed over the intersection of old and new participants. Because `me` is not in `old_participants`, it is also not in `intersection`, so `intersection.lagrange::<C>(me)` computes a coefficient for a point outside the set — yielding a non-zero scalar with overwhelming probability. The resulting `secret` is therefore non-zero:

```rust
// src/dkg.rs:611-620
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?
    .unwrap_or_else(<C::Group as Group>::Field::zero);
``` [4](#0-3) 

`do_keyshare` is then called with this non-zero secret. Its very first action is `assert_keyshare_inputs`, which **does** check the inverse condition and returns a `ProtocolError`:

```rust
// src/dkg.rs:41-44
} else {
    if !old_participants.contains(me) {
        return Err(ProtocolError::AssertionFailed(
            format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
``` [5](#0-4) 

This error fires **before** the first `await` point — before `do_broadcast` is ever reached:

```rust
// src/dkg.rs:354-362
let (old_verification_key, old_participants) =
    assert_keyshare_inputs(me, &secret, old_reshare_package)?;  // aborts here

// ...
let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;  // never reached
``` [6](#0-5) 

All other honest participants have already entered `do_broadcast` and are blocked in `recv_from_others` waiting for `me`'s broadcast message, which will never arrive: [7](#0-6) 

The reshare protocol is permanently stalled for every honest participant in the session.

---

### Impact Explanation

**High — Permanent denial of reshare for honest parties.**

Any participant who is not in `old_participants` but passes `old_signing_key = Some(...)` to `reshare()` will:
1. Successfully construct a protocol object (initialization succeeds).
2. Fail silently inside the async future before emitting a single message.
3. Leave every other honest participant blocked indefinitely in the broadcast round.

This permanently prevents the reshare (and by extension any subsequent signing) from completing for the entire participant set. The same path is reachable through `refresh()`, which also delegates to `assert_reshare_keys_invariants` and `do_reshare`. [8](#0-7) 

---

### Likelihood Explanation

**Medium.** The entry point is the public `reshare()` API. Any library caller — including a misconfigured honest node or a malicious participant who has been added to the new participant set but was never in the old one — can trigger this by supplying a non-`None` signing key. No cryptographic material or privileged access is required; only the ability to call `reshare()` with a crafted argument.

---

### Recommendation

Add the missing symmetric guard in `assert_reshare_keys_invariants` immediately after the existing check:

```rust
// After line 667 in src/dkg.rs
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not present in the old participant list but provided a share"
    )));
}
```

This mirrors the existing check and ensures both invalid combinations are rejected at initialization time — before the protocol object is handed to the caller — consistent with how all other parameter errors are surfaced in `assert_key_invariants` and `assert_sign_inputs`. [2](#0-1) 

---

### Proof of Concept

```
Setup:
  old_participants = [P1, P2, P3], old_threshold = 2
  new_participants = [P1, P2, P3, P4]   // P4 is a new joiner

Attacker action (P4):
  reshare(
      old_participants = [P1, P2, P3],
      old_threshold    = 2,
      old_signing_key  = Some(<any SigningShare>),  // P4 was never in old set
      old_public_key   = <valid key>,
      new_participants = [P1, P2, P3, P4],
      new_threshold    = 3,
      me               = P4,
      rng              = ...,
  )
  // Returns Ok(protocol) — assert_reshare_keys_invariants does not reject this

P1, P2, P3 each call reshare() correctly and enter do_broadcast, waiting for P4's message.

P4's protocol is driven (poke):
  → do_reshare computes intersection = {P1,P2,P3} ∩ {P1,P2,P3,P4} = {P1,P2,P3}
  → intersection.lagrange::<C>(P4) returns a non-zero scalar (P4 not in intersection)
  → secret = non_zero_lambda * signing_share ≠ 0
  → assert_keyshare_inputs: me (P4) not in old_participants, secret ≠ 0 → ProtocolError
  → P4 never sends broadcast message

Result: P1, P2, P3 are permanently blocked waiting for P4's Round 1 broadcast.
        Reshare is permanently denied for all honest parties.
```

### Citations

**File:** src/dkg.rs (L39-45)
```rust
        } else {
            //  return error if me is part of the old participants set
            if !old_participants.contains(me) {
                return Err(ProtocolError::AssertionFailed(
                    format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
            }
        }
```

**File:** src/dkg.rs (L354-362)
```rust
    let (old_verification_key, old_participants) =
        assert_keyshare_inputs(me, &secret, old_reshare_package)?;

    // Start Round 1
    // Step 1.2
    let mut my_session_id = [0u8; 32]; // 256 bits
    rng.fill_bytes(&mut my_session_id);
    // Step 1.3 & 2.1
    let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;
```

**File:** src/dkg.rs (L611-620)
```rust
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

**File:** src/lib.rs (L165-172)
```rust
    let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
        old_participants,
        me,
        threshold,
        old_signing_key,
        threshold,
        old_participants,
    )?;
```

**File:** src/protocol/helpers.rs (L19-24)
```rust
    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }
```
