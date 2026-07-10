### Title
Inconsistent Participant-Role Validation Between `assert_reshare_keys_invariants` and `assert_keyshare_inputs` Causes Permanent Reshare DoS — (`File: src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` (the public pre-flight guard for `reshare`) only checks one direction of the participant-role / key-presence invariant: it rejects an *old* participant that supplies no key, but it does **not** reject a *new* participant (absent from `old_participants`) that supplies a non-zero `old_signing_key`. The internal guard `assert_keyshare_inputs`, called inside `do_keyshare`, does check the inverse direction and aborts immediately — before any network message is sent. Because the public guard passes while the internal guard fails, the malicious new participant's protocol future terminates silently without ever broadcasting its session-id, causing every honest co-participant to block indefinitely inside `do_broadcast` / `recv_from_others`, permanently stalling the reshare.

---

### Finding Description

**Root cause — the gap in `assert_reshare_keys_invariants`** [1](#0-0) 

```rust
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
```

The comment describes the *inverse* of what the code enforces. The code rejects `(me ∈ old) ∧ (key = None)` but silently accepts `(me ∉ old) ∧ (key = Some(_))`. The symmetric check is absent.

**Internal guard that does enforce the inverse — but too late** [2](#0-1) 

```rust
} else {
    //  return error if me is part of the old participants set
    if !old_participants.contains(me) {
        return Err(ProtocolError::AssertionFailed(
            format!("{me:?} is running Resharing with a non-zero share but does not belong to the old participant set")));
    }
}
```

`assert_keyshare_inputs` is called at the very top of `do_keyshare`, before any channel message is sent. [3](#0-2) 

**How a non-zero secret reaches `assert_keyshare_inputs`**

In `do_reshare`, when `old_signing_key = Some(fake)` and `me ∉ old_participants`, the code computes: [4](#0-3) 

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
```

Because `me ∉ intersection`, `lagrange` evaluates the Lagrange basis polynomial at `me` using the intersection points — a well-defined, non-zero scalar. The product `lambda * fake_key.to_scalar()` is therefore non-zero, and `assert_keyshare_inputs` aborts with `ProtocolError::AssertionFailed` before `do_keyshare` sends a single byte.

**Why honest parties hang**

The first network action in `do_keyshare` is a reliable broadcast of a session-id: [5](#0-4) 

```rust
let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;
```

`reliable_broadcast_receive_all` loops unconditionally waiting for a `Send` message from every session-id slot: [6](#0-5) 

```rust
loop {
    if !is_simulated_vote {
        match chan.recv(wait).await {
            Ok(value) => (from, (sid, vote)) = value,
            _ => continue,
        };
    }
    ...
```

There is no timeout. Because the malicious participant's future exits before reaching `do_keyshare`, it never sends its `Send` message. The `finish_ready` flag for its session-id slot is never set, so the `all(|x| x.finish_ready)` termination condition is never satisfied: [7](#0-6) 

Every honest participant blocks indefinitely.

**The public API entry point** [8](#0-7) 

`reshare` is a fully public function. Any participant can supply arbitrary values for `old_signing_key`.

---

### Impact Explanation

A single malicious new participant (one that is legitimately listed in `new_participants` but absent from `old_participants`) can supply a non-zero `old_signing_key`. The public guard `assert_reshare_keys_invariants` accepts the call; the internal guard `assert_keyshare_inputs` aborts the future before any message is sent. All honest co-participants block indefinitely inside `do_broadcast`, permanently preventing the reshare from completing. Because the library exposes no timeout and no mechanism to identify which participant failed to broadcast, honest parties cannot recover without out-of-band coordination.

**Impact category**: High — Permanent denial of reshare for honest parties under valid protocol inputs and documented trust assumptions.

---

### Likelihood Explanation

The attack requires only that the adversary control one participant slot in the new participant set and pass a non-`None` value for `old_signing_key`. No cryptographic material from the old epoch is needed; any non-zero scalar suffices. The public API imposes no restriction on this parameter for new participants, and the pre-flight check explicitly misses this case. The attack is deterministic and reproducible on every reshare attempt.

---

### Recommendation

Add the missing symmetric check to `assert_reshare_keys_invariants` so that the two guards are logical negations of each other:

```rust
// Reject old participant without a key
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
// Reject new participant with a key (symmetric, currently missing)
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not present in the old participant list but provided a share"
    )));
}
```

This mirrors the invariant already enforced by `assert_keyshare_inputs` and closes the gap before any protocol future is spawned.

---

### Proof of Concept

1. Run a DKG with `old_participants = [P0, P1, P2]`, `old_threshold = 2`.
2. Introduce a new participant `P3` (not in `old_participants`).
3. `P3` calls `reshare(old_participants, 2, Some(arbitrary_signing_share), old_pk, [P0,P1,P2,P3], 2, P3, rng)`.
4. `assert_reshare_keys_invariants` returns `Ok` — the check `old_participants.contains(P3) && old_signing_key.is_none()` is `false && _ = false`.
5. Inside `do_reshare`, `intersection.lagrange::<C>(P3)` returns a non-zero scalar; `secret` is non-zero.
6. `do_keyshare` calls `assert_keyshare_inputs(P3, &secret, Some((old_pk, old_participants)))`: `!old_participants.contains(P3)` is `true` and `is_zero_secret` is `false` → `ProtocolError::AssertionFailed` is returned immediately.
7. `P3`'s future exits without sending any message.
8. `P0`, `P1`, `P2` each enter `do_broadcast` and block forever waiting for `P3`'s session-id `Send` message.
9. The reshare never completes; all honest parties are permanently stalled.

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

**File:** src/dkg.rs (L353-355)
```rust
    // Make sure you do not call do_keyshare with zero as secret on an old participant
    let (old_verification_key, old_participants) =
        assert_keyshare_inputs(me, &secret, old_reshare_package)?;
```

**File:** src/dkg.rs (L362-362)
```rust
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

**File:** src/dkg.rs (L661-667)
```rust
    // Step 1.1
    // if me is not in the old participant set then ensure that old_signing_key is None
    if old_participants.contains(me) && old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "party {me:?} is present in the old participant list but provided no share"
        )));
    }
```

**File:** src/protocol/echo_broadcast.rs (L173-183)
```rust
    loop {
        // Am I handling a simulated vote sent by me to myself?
        if !is_simulated_vote {
            // The recv should be failure-free
            // This translates to ignoring the received message when deemed wrong
            // types of the received answers are (Participant, (usize, MessageType))
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
        }
```

**File:** src/protocol/echo_broadcast.rs (L323-325)
```rust
                    if state.iter().all(|x| x.finish_ready) {
                        return Ok(vote_output);
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
