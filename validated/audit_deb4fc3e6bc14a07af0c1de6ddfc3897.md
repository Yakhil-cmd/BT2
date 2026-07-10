### Title
Malicious Participant Permanently Blocks DKG/Reshare/Refresh by Withholding Echo-Broadcast `Send` Message — (File: `src/protocol/echo_broadcast.rs`)

---

### Summary

`reliable_broadcast_receive_all` runs N parallel broadcast sessions (one per participant) and only returns when **all** N sessions have set `finish_ready`. A single malicious participant that never sends their `Send` message causes their session to stall permanently, blocking the entire function — and therefore every DKG, reshare, and refresh invocation — indefinitely.

---

### Finding Description

`reliable_broadcast_receive_all` maintains a `state` vector of `BroadcastProtocolState`, one entry per participant, indexed by session ID (`sid`). The sole exit condition for the happy path is:

```rust
if state.iter().all(|x| x.finish_ready) {
    return Ok(vote_output);
}
```

A session's `finish_ready` flag is only set to `true` after the delivery threshold of `Ready` messages is exceeded for that session. That threshold can only be reached if participants first echo the sender's `Send` message. If the sender never emits a `Send` message, no participant will ever echo it, no `Ready` messages will accumulate for that session, and `finish_ready` for that slot will remain `false` forever.

The early-termination guard that detects a malicious sender (lines 240–263) only fires when an `Echo` message is actually received for a session. If the sender is completely silent, no `Echo` messages arrive, the guard is never evaluated, and the loop spins indefinitely on `chan.recv(wait).await`.

`do_broadcast` — which wraps `reliable_broadcast_receive_all` — is called three times inside `do_keyshare`:

1. Session-ID negotiation (line 362)
2. Commitment + proof-of-knowledge broadcast (line 435)
3. Final success vote (line 531)

A malicious participant that participates in round 1 but goes silent in round 2 will cause every honest party to block permanently at the second `do_broadcast` call, with no recovery path.

---

### Impact Explanation

**High — Permanent denial of key generation, reshare, and refresh for all honest parties.**

Once the protocol stalls inside `reliable_broadcast_receive_all`, there is no timeout, no partial-completion path, and no error return. All honest participants are stuck in an infinite `await` loop. No new DKG, reshare, or refresh can be initiated on the same channel, and any signing infrastructure that depends on completing key generation is permanently unavailable.

---

### Likelihood Explanation

Any single participant in the protocol — including a newly joining party in a reshare — can trigger this by simply not transmitting their `Send` message after the session-ID round. No cryptographic capability is required; the attacker only needs to stop sending. The attack is reachable from the first call to `do_broadcast` inside `do_keyshare` and requires no prior trust or elevated privilege beyond being a listed participant.

---

### Recommendation

Replace the all-or-nothing exit condition with a mechanism that can declare a session permanently failed when it is provably uncompletable:

- After all other N−1 sessions have delivered, if a session has received zero `Send` messages and zero `Echo` messages, return a `ProtocolError` identifying the silent participant rather than looping.
- Alternatively, track a "sessions delivered" counter alongside `vote_output` and return once the counter reaches N, substituting an error entry for any session that could not deliver.

This mirrors the fix applied in Perennial M-11: allow the protocol to make forward progress on completed sub-operations rather than gating the entire output on one unavailable participant.

---

### Proof of Concept

Setup: N = 4 participants A, B, C (honest), D (malicious).

1. All four call `do_keyshare` → `do_broadcast` for session-ID negotiation. D participates honestly here so the first broadcast completes.
2. All four enter the second `do_broadcast` (commitment + proof). D calls `reliable_broadcast_send` but then drops the connection — it never transmits `MessageType::Send(...)` to any peer.
3. A, B, C each receive `Send` from one another, echo, and accumulate `Ready` messages. Their three sessions (`sid` = index of A, B, C) each reach the delivery threshold and set `finish_ready = true`.
4. D's session (`sid` = index of D) has `finish_send = false`, `finish_echo = false`, `finish_ready = false` — no message was ever received for it.
5. The check `state.iter().all(|x| x.finish_ready)` evaluates to `false` because D's slot is still `false`.
6. The loop calls `chan.recv(wait).await` again. No further messages will ever arrive for D's session. The function never returns.
7. A, B, and C are permanently blocked; DKG fails to produce any output.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** src/protocol/echo_broadcast.rs (L240-263)
```rust
                // This check has to be done after counting the simulated value.
                else if !state_sid.finish_amplification {
                    // calculate the total number of echos already collected
                    let received_echo_cnt = state_sid.data_echo.get_sum_counters();
                    // calculate the number of echo to be received
                    let non_received_echo_cnt = n - received_echo_cnt;
                    // iterate over the state_sid.data_echo array
                    let mut is_enough = false;
                    for (_, cnt) in state_sid.data_echo.iter() {
                        // verify whether there is enough votes in at
                        // least one slot to exceed the threshold
                        if cnt + non_received_echo_cnt > echo_t {
                            is_enough = true;
                            break;
                        }
                    }

                    // if not enough echo votes left for hitting the threshold
                    // then we know that the sender is malicious
                    if !is_enough {
                        return Err(ProtocolError::AssertionFailed(format!(
                            "The original sender in session {sid:?} is malicious! Could not collect enough echo votes to meet the threshold"
                        )));
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

**File:** src/dkg.rs (L362-362)
```rust
    let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;
```

**File:** src/dkg.rs (L435-441)
```rust
    let commitments_and_proofs_map = do_broadcast(
        &mut chan,
        &participants,
        me,
        (commitment, proof_of_knowledge),
    )
    .await?;
```

**File:** src/dkg.rs (L531-531)
```rust
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```
