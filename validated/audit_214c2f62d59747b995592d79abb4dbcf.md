### Title
`broadcast_success` Never Broadcasts Failure Despite Documented Intent, Enabling Permanent DKG Denial - (File: src/dkg.rs)

---

### Summary

The `broadcast_success` function in `src/dkg.rs` carries a doc-comment stating it should accept an error input and broadcast failure when one occurs. However, the function signature has no such parameter and always broadcasts `(true, session_id)`. The failure-broadcasting path is completely unreachable. A malicious participant who sends an invalid secret share to exactly one honest participant causes that participant to abort locally before reaching `broadcast_success`, while all remaining honest participants block indefinitely inside `do_broadcast` waiting for a message that will never arrive.

---

### Finding Description

The function comment at `src/dkg.rs` lines 302–306 reads:

```
/// This function takes err as input.
/// If err is None then broadcast success
/// otherwise, broadcast failure
/// If during broadcast it receives an error then propagates it
/// This function is used in the final round of DKG
```

Yet the actual signature and body are:

```rust
async fn broadcast_success(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    session_id: HashOutput,
) -> Result<(), ProtocolError> {
    // broadcast node me succeded
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
```

There is no `err` parameter. The function unconditionally broadcasts `(true, session_id)`. The failure-broadcasting mechanism described in the comment is never reachable. [1](#0-0) 

`broadcast_success` is called only at the very end of `do_keyshare`, after all per-participant checks have passed: [2](#0-1) 

If any check fails before that point — for example `validate_received_share` at line 522 — the participant returns an error and never calls `broadcast_success`: [3](#0-2) 

The remaining honest participants are blocked inside `reliable_broadcast_receive_all`, which loops unconditionally until every participant's `finish_ready` flag is set: [4](#0-3) 

Because the aborting participant never sends its broadcast message, the `state.iter().all(|x| x.finish_ready)` condition is never satisfied and the loop never exits: [5](#0-4) 

---

### Impact Explanation

A malicious participant can selectively send an invalid secret share to exactly one honest participant (via the private channel at line 505) while sending valid shares to all others: [6](#0-5) 

The targeted honest participant aborts with `ProtocolError::InvalidSecretShare` before reaching `broadcast_success`. All other honest participants proceed to `broadcast_success` and block indefinitely waiting for the aborted participant's broadcast. Because the `Protocol` trait exposes no abort or cancel mechanism, and `reliable_broadcast_receive_all` has no timeout, the DKG session is permanently stalled for every remaining honest party. [7](#0-6) 

This matches: **High — Permanent denial of key generation for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

Any participant in the DKG session can trivially craft an invalid secret share for a single target. The private channel (`send_private`) is the intended delivery mechanism for shares, so no special network capability is required. The attacker only needs to be a legitimate protocol participant.

---

### Recommendation

Implement the failure-broadcasting mechanism as described in the existing comment. `broadcast_success` should accept an optional error flag, broadcast `(false, session_id)` when a local check has failed, and all participants should abort gracefully upon receiving any `false` vote. This mirrors the intent already expressed in the doc-comment and eliminates the indefinite-wait condition.

---

### Proof of Concept

1. Participants `P1, P2, P3` run `do_keyshare`.
2. Malicious participant `M` sends a valid secret share to `P2` and `P3` but an intentionally invalid share to `P1`.
3. `P1` calls `validate_received_share` at line 522, detects `InvalidSecretShare(M)`, and returns `Err(...)` — never reaching `broadcast_success` at line 531.
4. `P2` and `P3` pass all checks, call `broadcast_success`, and enter `do_broadcast` → `reliable_broadcast_receive_all`.
5. `reliable_broadcast_receive_all` loops forever waiting for `P1`'s `Ready` message, which never arrives.
6. The DKG session is permanently stalled for `P2` and `P3` with no way to recover, because the `Protocol` trait provides no abort path and the failure-broadcast path in `broadcast_success` was never implemented. [8](#0-7)

### Citations

**File:** src/dkg.rs (L302-338)
```rust
/// This function takes err as input.
/// If err is None then broadcast success
/// otherwise, broadcast failure
/// If during broadcast it receives an error then propagates it
/// This function is used in the final round of DKG
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
}
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

**File:** src/dkg.rs (L519-528)
```rust
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        // Step 5.3
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
    }
```

**File:** src/dkg.rs (L530-532)
```rust
    // Step 5.4 and Step 5.5
    broadcast_success(&mut chan, &participants, me, session_id).await?;

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

**File:** src/protocol/echo_broadcast.rs (L320-325)
```rust
                    // if all the ready slots are set to true
                    // then all sessions have ended successfully
                    // we can thus output that the n instances of the broadcast protocols have succeeded
                    if state.iter().all(|x| x.finish_ready) {
                        return Ok(vote_output);
                    }
```

**File:** src/protocol/mod.rs (L51-64)
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
```
