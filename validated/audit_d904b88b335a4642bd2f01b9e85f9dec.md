### Title
Single Malicious Participant Causes Permanent DKG Abort via Wrong `session_id` in `broadcast_success` — (`src/dkg.rs`)

### Summary

In `broadcast_success` (called as the final step of `do_keyshare`), each participant broadcasts `(true, session_id)` via the echo broadcast protocol. After delivery, the code checks that every participant's delivered `session_id` equals the local `session_id`. A single malicious participant can broadcast `(true, wrong_session_id)` — a value the echo broadcast protocol will reliably deliver to all honest parties — causing the check to fail on every honest node and aborting DKG permanently. This violates the documented BFT invariant that DKG must complete when at most `MaxFaulty = floor((N-1)/3)` participants are malicious.

### Finding Description

`broadcast_success` in `src/dkg.rs` calls `do_broadcast` to collect a `(bool, HashOutput)` tuple from every participant, then enforces:

```rust
if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
    return Err(ProtocolError::AssertionFailed(
        "A participant broadcast the wrong session id. Aborting Protocol!"
    ));
}
``` [1](#0-0) 

`do_broadcast` wraps the echo broadcast protocol (`reliable_broadcast_receive_all`). For n=4, `echo_ready_thresholds(4)` returns `echo_t=2, ready_t=1`: [2](#0-1) 

Delivery of a sender's value requires `> 2 * ready_t = 2` ready votes. With 3 honest parties all echoing the malicious party's `(true, wrong_session_id)`, 3 echo votes exceed `echo_t=2`, triggering 3 ready votes which exceed `2*ready_t=2`. The echo broadcast protocol therefore **reliably delivers** `(true, wrong_session_id)` to all honest parties for the malicious party's slot. [3](#0-2) 

After `do_broadcast` returns, every honest party's `vote_list` contains the malicious `wrong_session_id`. The equality check at line 321 fails on all honest nodes, and `do_keyshare` returns `ProtocolError::AssertionFailed` before outputting any key material: [4](#0-3) 

The attack is possible even though all honest parties have already successfully completed share verification (Steps 5.1–5.3) and hold valid signing shares — the abort happens in the very last step.

### Impact Explanation

All honest parties abort DKG with `ProtocolError::AssertionFailed("A participant broadcast the wrong session id...")`. No key output is produced. The same attack applies to reshare and refresh, since they all call `do_keyshare` and reach the same `broadcast_success` call. [5](#0-4) 

Impact: **High — Permanent denial of key generation, reshare, and refresh for all honest parties.**

### Likelihood Explanation

- Requires only one malicious participant out of four (n=4, t=1), which is exactly the documented BFT tolerance boundary.
- The malicious participant needs only to send a different `HashOutput` in the final broadcast round — no cryptographic break required.
- The attack is deterministic and reproducible every time DKG is attempted.
- The `session_id` check is entirely superfluous for honest parties (the session_id was already agreed upon in Round 1 via echo broadcast), making this a pure implementation defect.

### Recommendation

Remove the `session_id` equality check from `broadcast_success`. The session_id is already bound into all prior cryptographic material (commitments, proofs of knowledge, commitment hashes) via `domain_separate_hash` in Round 2. The final broadcast round only needs to confirm that all parties set the boolean flag to `true`. The session_id re-check adds no security value for honest parties but provides a trivial griefing vector for malicious ones. [6](#0-5) 

### Proof of Concept

```
n=4, t=1 (MaxFaulty=1 per documented BFT threshold)
Participants: P1 (honest), P2 (honest), P3 (honest), P4 (malicious)

Rounds 1–5: all honest parties complete normally, hold valid signing shares.

Round 5.4 (broadcast_success):
  P1 broadcasts (true, session_id)
  P2 broadcasts (true, session_id)
  P3 broadcasts (true, session_id)
  P4 broadcasts (true, RANDOM_WRONG_HASH)   ← attacker-controlled

Echo broadcast for P4's slot (n=4, echo_t=2, ready_t=1):
  P1, P2, P3 each echo (true, RANDOM_WRONG_HASH)  → 3 echoes > echo_t=2
  P1, P2, P3 each send Ready(true, RANDOM_WRONG_HASH) → 3 ready > 2*ready_t=2
  → All honest parties deliver (true, RANDOM_WRONG_HASH) for P4's slot

vote_list check at line 321:
  RANDOM_WRONG_HASH != session_id  → AssertionFailed on P1, P2, P3

Result: DKG permanently aborted for all honest parties.
```

### Citations

**File:** src/dkg.rs (L307-338)
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
}
```

**File:** src/dkg.rs (L530-537)
```rust
    // Step 5.4 and Step 5.5
    broadcast_success(&mut chan, &participants, me, session_id).await?;

    // Return the key pair
    Ok(KeygenOutput {
        private_share: SigningShare::new(my_signing_share),
        public_key: verifying_key,
    })
```

**File:** src/protocol/echo_broadcast.rs (L67-78)
```rust
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    // case where no malicious parties are assumed: when n <= 3/
    // In this case the echo and ready thresholds are both 0
    // later we compare if we have collected more votes than these thresholds
    if n <= 3 {
        return (0, 0);
    }
    // we should always have n >= 3*threshold + 1
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
}
```

**File:** src/protocol/echo_broadcast.rs (L293-325)
```rust
                if state_sid.data_ready.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > 2 * ready_t
                {
                    // skip all types of messages sent for session sid from now on
                    state_sid.finish_send = true;
                    state_sid.finish_echo = true;
                    state_sid.finish_ready = true;

                    // return a map of participant data
                    let p = participants
                        .get_participant(sid)
                        .ok_or_else(|| ProtocolError::Other("Missing participant".to_string()))?;
                    // make a list of data and return them
                    vote_output.put(p, data.clone());

                    // Output error if the received vote after broadcast is not
                    // the same as the one originally sent
                    if sid == participants.index(me)? && MessageType::Send(data) != send_vote {
                        return Err(ProtocolError::AssertionFailed(
                            "Too many malicious parties, way above the assumed threshold:
                            The message output after the broadcast protocol is not the same as
                            the one originally sent by me"
                                .to_string(),
                        ));
                    }

                    // if all the ready slots are set to true
                    // then all sessions have ended successfully
                    // we can thus output that the n instances of the broadcast protocols have succeeded
                    if state.iter().all(|x| x.finish_ready) {
                        return Ok(vote_output);
                    }
```
