### Title
Incomplete Dual-State Validation in `assert_reshare_keys_invariants` Allows New Joiner to Bypass Pre-Protocol Checks and Abort Resharing for All Participants — (`File: src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` enforces only one direction of the new-joiner / old-participant invariant. A new joiner (not in `old_participants`) who supplies a non-`None` `old_signing_key` passes the pre-protocol validation gate, causing the resharing session to abort mid-execution with a `ProtocolError` rather than being rejected at initialization time with an `InitializationError`. All honest participants are left waiting for the malicious new joiner's Round-1 broadcast, permanently stalling the resharing session.

---

### Finding Description

In `assert_reshare_keys_invariants` the comment on line 662 explicitly states the intended invariant:

> "if me is not in the old participant set then ensure that `old_signing_key` is None"

However, the code only enforces the **opposite** direction:

```rust
// src/dkg.rs  lines 662-667
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
```

The symmetric guard — rejecting a new joiner who supplies a non-`None` share — is entirely absent:

```rust
// MISSING:
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(...));
}
```

Because `assert_reshare_keys_invariants` is the sole pre-flight validation called by the public `reshare()` entry point before the async future is constructed, the invalid parameter combination silently passes and `reshare()` returns `Ok(protocol)`. [1](#0-0) 

When the protocol future is later polled, `do_reshare` computes:

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)          // me ∉ intersection, but returns a valid non-zero scalar
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?
    .unwrap_or_else(<C::Group as Group>::Field::zero);
``` [2](#0-1) 

Because `me` is not in the intersection, `lagrange::<C>(me)` evaluates the Lagrange basis polynomial at `me`'s scalar value over the intersection set — a valid, non-zero result. This produces a non-zero `secret`. The error is only caught inside `do_keyshare` by `assert_keyshare_inputs`:

```rust
} else {
    // return error if me is not part of the old participants set
    if !old_participants.contains(me) {
        return Err(ProtocolError::AssertionFailed(
            format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
    }
}
``` [3](#0-2) 

Critically, `assert_keyshare_inputs` is called **before** any network I/O in `do_keyshare` — before the Round-1 `do_broadcast`. The malicious participant's instance aborts without ever sending its session-ID broadcast. [4](#0-3) 

All other participants block indefinitely on `recv_from_others` waiting for the missing broadcast, stalling the entire resharing session.

---

### Impact Explanation

**Impact: High — Permanent denial of reshare for honest parties.**

A malicious new joiner can reliably abort any resharing session they are invited to join. Because the pre-validation gate (`assert_reshare_keys_invariants`) passes, the caller receives `Ok(protocol)` and begins coordinating with honest participants. When the future is polled, the malicious participant's instance silently aborts before emitting its Round-1 message. Every honest participant blocks on `recv_from_others` for the missing broadcast. The resharing cannot complete; honest parties cannot obtain new key shares or change the participant set. [5](#0-4) 

---

### Likelihood Explanation

Any participant invited as a new joiner to a resharing session controls the `old_signing_key` argument they pass to `reshare()`. Supplying `Some(arbitrary_share)` instead of `None` is a single-line change requiring no cryptographic knowledge. The missing guard is documented in the code's own comment, making the gap easy to identify. The attack is deterministic and requires no coordination.

---

### Recommendation

Add the symmetric guard immediately after the existing check in `assert_reshare_keys_invariants`:

```rust
// Existing check (old participant must supply a share)
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
// ADD: new joiner must NOT supply a share
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not in the old participant list but provided a share"
    )));
}
```

This makes the invariant stated in the comment enforceable at initialization time, consistent with how `refresh()` already rejects a missing share at the `InitializationError` level. [6](#0-5) 

---

### Proof of Concept

```
Participants: old = {P1, P2, P3}, new = {P1, P2, P3, P4 (new joiner)}
Threshold: 2 → 2

Step 1: P4 (new joiner, not in old_participants) calls:
    reshare(
        old_participants = [P1, P2, P3],
        old_threshold    = 2,
        old_signing_key  = Some(arbitrary_SigningShare),  // ← invalid, should be None
        old_public_key   = valid_pk,
        new_participants = [P1, P2, P3, P4],
        new_threshold    = 2,
        me               = P4,
        rng              = ...,
    )

Step 2: assert_reshare_keys_invariants passes — old_participants.contains(P4) == false,
        so the only guard (contains && is_none) is not triggered.
        reshare() returns Ok(protocol).

Step 3: Protocol is run. do_reshare computes:
        intersection = {P1,P2,P3} ∩ {P1,P2,P3,P4} = {P1,P2,P3}
        lagrange(P4) over {P1,P2,P3} → non-zero scalar λ
        secret = λ * arbitrary_share.to_scalar()  ← non-zero

Step 4: do_keyshare → assert_keyshare_inputs:
        secret != 0 AND old_participants.contains(P4) == false
        → ProtocolError::AssertionFailed  (before any broadcast)

Step 5: P1, P2, P3 block on recv_from_others waiting for P4's Round-1 session-ID.
        Resharing session stalls permanently.
```

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
