### Title
Missing Inverse Condition in `assert_reshare_keys_invariants` Allows New Participant with Spurious Old Key to Bypass Initialization and Abort Reshare at Runtime - (File: src/dkg.rs)

### Summary

`assert_reshare_keys_invariants` in `src/dkg.rs` checks only one direction of the participant-membership / signing-key consistency invariant. It rejects an old participant that supplies no key, but it silently accepts a **new** participant (one absent from `old_participants`) that supplies a non-`None` `old_signing_key`. The error is caught later, inside the running async protocol, causing the reshare to abort mid-execution and leaving every honest participant waiting indefinitely for messages that will never arrive.

### Finding Description

The pre-flight validation function `assert_reshare_keys_invariants` is the sole `InitializationError`-level gate before the reshare protocol is launched. Its comment explicitly states the intended invariant:

> "if me is not in the old participant set then ensure that old_signing_key is None"

The implemented code, however, only enforces the **opposite** half of that invariant:

```rust
// src/dkg.rs lines 662-667
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
``` [1](#0-0) 

The missing branch — `!old_participants.contains(me) && old_signing_key.is_some()` — is never checked. When a new participant supplies a non-`None` `old_signing_key`, `assert_reshare_keys_invariants` returns `Ok(...)` and `reshare()` proceeds to construct and return the protocol future. [2](#0-1) 

Inside `do_reshare`, the secret is computed by multiplying the supplied key by the Lagrange coefficient of `me` over the intersection set. Because `me` is absent from `old_participants`, it is also absent from `intersection`, yet `lagrange` still produces a valid non-zero scalar (it computes the Lagrange basis polynomial for a point outside the set, which is mathematically defined):

```rust
// src/dkg.rs lines 611-620
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

This non-zero secret is then passed into `do_keyshare`, where `assert_keyshare_inputs` finally catches the inconsistency and returns `ProtocolError::AssertionFailed`:

```rust
// src/dkg.rs lines 40-44
} else {
    if !old_participants.contains(me) {
        return Err(ProtocolError::AssertionFailed(
            format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
    }
}
``` [4](#0-3) 

At this point the malicious participant's async future terminates with an error. It stops emitting protocol messages. All honest participants are blocked inside `do_broadcast` / `recv_from_others` waiting for messages from every participant in the new set. Because no timeout is enforced, they wait indefinitely. [5](#0-4) 

### Impact Explanation

A malicious new joiner (a participant present in `new_participants` but absent from `old_participants`) can deliberately supply a non-`None` `old_signing_key`. The initialization gate passes, the protocol starts, and the malicious participant's instance aborts silently at runtime. Every honest participant's reshare instance then hangs indefinitely waiting for the missing broadcast messages, permanently denying the reshare for the current session.

This maps to: **High — Permanent denial of reshare for honest parties under valid protocol inputs and documented trust assumptions.**

### Likelihood Explanation

Any participant who is a new joiner in a reshare can trigger this by passing any non-`None` value as `old_signing_key`. No cryptographic material needs to be known; any arbitrary `SigningShare` value suffices. The attacker only needs to be included in the new participant set, which is a normal and expected role in a reshare operation.

### Recommendation

Add the symmetric check to `assert_reshare_keys_invariants`:

```rust
// Existing check (old participant without key)
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
// Missing check (new participant with key)
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not present in the old participant list but provided a share"
    )));
}
```

This mirrors the complete bidirectional check already present in `assert_keyshare_inputs` and surfaces the error at `InitializationError` level before the protocol future is ever constructed.

### Proof of Concept

1. Run a keygen with participants `[P0, P1, P2]`, threshold 2.
2. Initiate a reshare to `[P0, P1, P2, P3]` (P3 is a new joiner).
3. For P3's call to `reshare(...)`, pass `old_signing_key = Some(<any SigningShare>)` instead of `None`.
4. Observe that `assert_reshare_keys_invariants` returns `Ok(...)` — no `InitializationError` is raised.
5. The protocol future is returned and execution begins.
6. Inside `do_keyshare`, `assert_keyshare_inputs` fires `ProtocolError::AssertionFailed` and P3's future terminates.
7. P0, P1, P2 remain blocked in `do_broadcast` waiting for P3's session-id broadcast that never arrives. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** src/dkg.rs (L22-55)
```rust
/// This function prevents calling keyshare function with inproper inputs
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

**File:** src/dkg.rs (L637-669)
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
