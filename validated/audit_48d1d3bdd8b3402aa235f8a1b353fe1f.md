### Title
Malicious Participant Permanently Blocks DKG/Reshare by Sending an Invalid Secret Share, Leaving All Other Honest Parties Indefinitely Stuck — (`src/dkg.rs`)

---

### Summary

A single malicious participant in the DKG, reshare, or refresh protocol can permanently deny key generation for all other honest parties. By sending a deliberately invalid secret share to exactly one honest participant, the attacker causes that participant to abort before reaching `broadcast_success`. Because the echo broadcast used in `broadcast_success` requires **all N** broadcast instances to complete before returning, and the aborting participant never sends their SEND message, every remaining honest participant is left waiting indefinitely with no timeout, no abort-notification mechanism, and no recovery path.

---

### Finding Description

The core of DKG, reshare, and refresh is implemented in `do_keyshare` in `src/dkg.rs`. The protocol proceeds through five rounds. In Round 5, each participant receives secret share evaluations from every other participant and validates them:

```
// Step 5.1
for (from, signing_share_from) in
    recv_from_others(&chan, wait_round_3, &participants, me).await?
{
    // Step 5.2
    validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
    ...
}
// Step 5.4 and Step 5.5
broadcast_success(&mut chan, &participants, me, session_id).await?;
``` [1](#0-0) 

`validate_received_share` verifies the received share against the sender's published commitment. If the share is invalid, it returns `Err(ProtocolError::InvalidSecretShare(from))`: [2](#0-1) 

The `?` operator propagates this error immediately out of `do_keyshare`. The aborting participant **never reaches `broadcast_success`** and therefore never sends their SEND message in the echo broadcast.

`broadcast_success` calls `do_broadcast`, which runs the echo broadcast protocol. The echo broadcast only returns when every one of the N parallel broadcast instances has completed:

```rust
if state.iter().all(|x| x.finish_ready) {
    return Ok(vote_output);
}
``` [3](#0-2) 

Because the aborting participant's broadcast instance never receives a SEND message, it can never progress to ECHO or READY, and `state.iter().all(|x| x.finish_ready)` is never true. All remaining honest participants block indefinitely inside `do_broadcast`.

The `recv_from_others` helper, used in every collection round, also waits unconditionally for all participants:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;
    ...
}
``` [4](#0-3) 

There is no timeout, no abort-notification broadcast, and no recovery mechanism anywhere in the library. The `Protocol` trait exposes only `poke()` and `message()`—no `abort()` or `cancel()`: [5](#0-4) 

---

### Impact Explanation

**High — Permanent denial of DKG, reshare, and refresh for honest parties.**

Once the attack is triggered:
- The honest participant who received the bad share aborts with `InvalidSecretShare`.
- Every other honest participant is permanently blocked inside `broadcast_success` → `do_broadcast` → echo broadcast, waiting for the aborting participant's broadcast instance that will never arrive.
- The library provides no mechanism to detect the stall, identify the cause, or restart cleanly. The caller has no in-library signal distinguishing "waiting for a slow peer" from "permanently stuck."
- DKG, reshare, and refresh are all affected because all three call `do_keyshare`: [6](#0-5) [7](#0-6) 

---

### Likelihood Explanation

**High.** Any single participant in the protocol can execute this attack:

1. The attacker is a legitimate protocol participant (no privilege required).
2. At step 4.6, each participant privately sends share evaluations to every other participant. The attacker simply sends a random or zero scalar to one chosen victim instead of the correct evaluation.
3. The victim's `validate_received_share` check will fail, causing the abort.
4. The attacker sends valid shares to all other participants, so they proceed normally into `broadcast_success` and block.

The attack requires only one malformed private message and is undetectable by the other participants until they realize the protocol has stalled. [8](#0-7) 

---

### Recommendation

1. **Add a failure-broadcast path.** When a participant detects a protocol error (e.g., `InvalidSecretShare`), it should broadcast a signed abort message identifying the culprit before terminating. Other participants can then abort cleanly and exclude the identified malicious party from a retry.

2. **Implement a partial-completion return in the echo broadcast.** The echo broadcast should be able to return a partial result (or a per-sender error) when a sender's instance cannot complete, rather than requiring all N instances to succeed.

3. **Expose a cancellation/timeout mechanism in the `Protocol` trait.** Callers need a way to abort a stalled protocol and receive a meaningful error, rather than waiting forever.

---

### Proof of Concept

**Setup:** 4 participants `[P1, P2, P3, P4]`, threshold = 2. `P1` is malicious.

**Steps:**

1. All participants run `keygen` / `do_keyshare` normally through Round 4.
2. At step 4.6, `P1` sends the correct share evaluation to `P2`, `P3`, but sends a random invalid scalar to `P4`.
3. `P4` receives `P1`'s invalid share in `recv_from_others` at step 5.1.
4. `validate_received_share` fails: `secret_share.verify()` returns `Error::InvalidSecretShare`, mapped to `ProtocolError::InvalidSecretShare(P1)`.
5. `P4`'s `do_keyshare` returns `Err(...)` immediately via `?`. `P4` never calls `broadcast_success`.
6. `P1`, `P2`, `P3` all reach `broadcast_success` and call `do_broadcast`. Each sends their own SEND message. They wait for all 4 broadcast instances (one per participant) to complete.
7. `P4`'s broadcast instance never receives a SEND message. `state[P4_index].finish_ready` is never set to `true`.
8. `state.iter().all(|x| x.finish_ready)` is never satisfied. `P1`, `P2`, `P3` block forever. [9](#0-8) [3](#0-2)

### Citations

**File:** src/dkg.rs (L259-286)
```rust
fn validate_received_share<C: Ciphersuite>(
    me: Participant,
    from: Participant,
    signing_share_from: &SigningShare<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> Result<(), ProtocolError> {
    let id = me.to_identifier::<C>()?;

    // The verification is exactly the same as the regular SecretShare verification;
    // however the required components are in different places.
    // Build a temporary SecretShare so what we can call verify().
    let secret_share = SecretShare::new(id, *signing_share_from, commitment.clone());

    // Verify the share. We don't need the result.
    // Identify the culprit if an InvalidSecretShare error is returned.
    secret_share.verify().map_err(|e| {
        if let Error::InvalidSecretShare { .. } = e {
            ProtocolError::InvalidSecretShare(from)
        } else {
            ProtocolError::AssertionFailed(format!(
                "could not
            extract the verification key matching the secret
            share sent by {from:?}"
            ))
        }
    })?;
    Ok(())
}
```

**File:** src/dkg.rs (L307-337)
```rust
async fn broadcast_success(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    session_id: HashOutput,
) -> Result<(), ProtocolError> {
    // broadcast node me succeded
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
    // unwrap here would never fail as the broadcast protocol ends only when the map is full
    let vote_list = vote_list
        .into_vec_or_none()
        .ok_or_else(|| ProtocolError::AssertionFailed("vote_list is empty".to_string()))?;
    // go through all the list of votes and check if any is fail or some does not contain the session id

    if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
        return Err(ProtocolError::AssertionFailed(
            "A participant
                broadcast the wrong session id. Aborting Protocol!"
                .to_string(),
        ));
    }

    if !vote_list.iter().all(|&(boolean, _)| boolean) {
        return Err(ProtocolError::AssertionFailed(
            "A participant
                seems to have failed its checks. Aborting Protocol!"
                .to_string(),
        ));
    }
    // Wait for all the tasks to complete
    Ok(())
```

**File:** src/dkg.rs (L499-506)
```rust
    for p in participants.others(me) {
        // securely send to each other participant a secret share
        // using the evaluation secret polynomial on the identifier of the recipient
        // should not panic as secret_coefficients are created internally
        let signing_share_to_p = secret_coefficients.eval_at_participant(p)?;
        // send the evaluation privately to participant p
        chan.send_private(wait_round_3, p, &signing_share_to_p)?;
    }
```

**File:** src/dkg.rs (L514-531)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        // Step 5.3
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
    }

    // Step 5.4 and Step 5.5
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```

**File:** src/dkg.rs (L540-554)
```rust
pub async fn do_keygen<C: Ciphersuite>(
    chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    mut rng: impl CryptoRngCore,
) -> Result<KeygenOutput<C>, ProtocolError> {
    let threshold = threshold.into();
    // pick share at random
    let secret = SigningKey::<C>::new(&mut rng).to_scalar();
    // call keyshare
    let keygen_output =
        do_keyshare::<C>(chan, participants, me, threshold, secret, None, &mut rng).await?;
    Ok(keygen_output)
}
```

**File:** src/dkg.rs (L600-634)
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
```

**File:** src/protocol/echo_broadcast.rs (L320-325)
```rust
                    // if all the ready slots are set to true
                    // then all sessions have ended successfully
                    // we can thus output that the n instances of the broadcast protocols have succeeded
                    if state.iter().all(|x| x.finish_ready) {
                        return Ok(vote_output);
                    }
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

**File:** src/protocol/mod.rs (L51-65)
```rust
pub trait Protocol {
    type Output;

    /// Poke the protocol, receiving a new action.
    ///
    /// The idea is that the protocol should be poked until it returns an error,
    /// or it returns an action with a return value, or it returns a wait action.
    ///
    /// Upon returning a wait action, that protocol will not advance any further
    /// until a new message arrives.
    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError>;

    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
}
```
