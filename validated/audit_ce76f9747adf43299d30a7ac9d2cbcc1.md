### Title
Permanent Protocol Hang via Participant Crash — No Timeout or Fallback in `recv_from_others` and `reliable_broadcast_receive_all` - (File: src/protocol/helpers.rs, src/protocol/echo_broadcast.rs)

---

### Summary

Every multi-round protocol in this library (DKG, reshare, refresh, signing) ultimately blocks on `recv_from_others` or the inner loop of `reliable_broadcast_receive_all`. Both functions wait indefinitely for every registered participant to deliver a message. There is no timeout, no abort signal, and no fallback path. A single malicious participant who joins a session and then stops responding after the first round permanently stalls the protocol for all honest parties, with no recovery path short of external intervention and a full protocol restart.

---

### Finding Description

**`recv_from_others` — `src/protocol/helpers.rs`** [1](#0-0) 

The function loops on `chan.recv(waitpoint).await` until `seen.full()` — i.e., until every participant except `me` has delivered exactly one message. The underlying `MessageBuffer::pop` call at the bottom of the call chain awaits on an unbounded MPSC channel with no timeout: [2](#0-1) 

If any participant never sends, `pop` never returns, `recv_from_others` never returns, and the calling coroutine is suspended forever.

**`reliable_broadcast_receive_all` — `src/protocol/echo_broadcast.rs`** [3](#0-2) 

The outer `loop` only exits when every one of the `n` broadcast sessions has reached the Ready threshold: [4](#0-3) 

If participant `P` sends its `Send` message (so the session for `P` is opened) but then goes silent before sending `Echo`, no other participant can ever accumulate enough Echo votes to advance that session. The early-abort check: [5](#0-4) 

only fires when an Echo vote is *received* that makes the threshold provably unreachable. A participant who simply stops sending never triggers this path; the loop waits forever.

**Call sites in `do_keyshare` — `src/dkg.rs`**

`recv_from_others` is called twice inside `do_keyshare`: [6](#0-5) [7](#0-6) 

`do_broadcast` (which wraps `reliable_broadcast_receive_all`) is called three times: [8](#0-7) [9](#0-8) [10](#0-9) 

Every one of these call sites is a hang point if any participant stops responding.

---

### Impact Explanation

A malicious participant who is admitted to a DKG, reshare, refresh, or signing session can permanently prevent that session from completing for all honest parties. The participant need only:

1. Complete Round 1 (broadcast session ID / commitment hash) so that honest nodes record them as active.
2. Go silent for any subsequent round.

All honest nodes will then block indefinitely at the next `recv_from_others` or `reliable_broadcast_receive_all` call. Because there is no timeout and no abort mechanism, the session can never be declared failed by the library itself. The honest parties are permanently denied the ability to produce a key or signature from that session.

This matches: **High — Permanent denial of signing, key generation, reshare, or refresh for honest parties under valid protocol inputs.**

---

### Likelihood Explanation

**Low-to-Medium.** Any participant who is legitimately admitted to a session (i.e., whose `Participant` ID is in the `ParticipantList`) can execute this attack with zero cryptographic capability — they simply stop sending after Round 1. The attack requires no leaked keys, no cryptographic break, and no external dependency. The only prerequisite is admission to the session, which is controlled by the application layer, not the library.

---

### Recommendation

1. **Add a per-round deadline / timeout** to `recv_from_others` and to the `chan.recv` call inside `reliable_broadcast_receive_all`. If the deadline expires before all expected messages arrive, return a `ProtocolError` identifying the non-responsive participant(s).
2. **Propagate the timeout error** up through `do_keyshare`, `do_keygen`, `do_reshare`, and the signing entry points so callers can detect the stall and restart with a different participant set.
3. **Consider a threshold-based receive**: for protocols that tolerate `f` failures, allow progress once `n − f` responses have arrived rather than requiring all `n`.

---

### Proof of Concept

```
Participants: {P0, P1, P2, P3}  threshold = 2

1. All four call do_keygen / do_keyshare.
2. Round 1: all four broadcast their session ID via do_broadcast.
   - P3 (malicious) sends its session-ID broadcast normally.
3. Round 2: all four are expected to send their commitment_hash via
   chan.send_many(wait_round_1, &commitment_hash).
   - P3 goes silent.
4. P0, P1, P2 each reach:
       recv_from_others(&chan, wait_round_1, &participants, me)
   and block forever waiting for P3's commitment_hash.
5. No timeout fires. The DKG session never completes.
   Honest parties P0–P2 are permanently denied their key shares.
```

The same scenario applies to every subsequent round (`do_broadcast` for commitments/proofs, `recv_from_others` for signing shares, `broadcast_success`) and to reshare, refresh, and all signing protocols that call the same helpers.

### Citations

**File:** src/protocol/helpers.rs (L6-26)
```rust
pub async fn recv_from_others<T>(
    chan: &SharedChannel,
    waitpoint: u64,
    participants: &ParticipantList,
    me: Participant,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let mut messages = Vec::with_capacity(participants.others(me).count());

    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
```

**File:** src/protocol/internal.rs (L245-255)
```rust
    async fn pop(&self, header: MessageHeader) -> (Participant, MessageData) {
        let receiver = {
            let mut messages_lock = self.messages.lock().expect("lock should not fail");
            messages_lock.entry(header).or_default().receiver.clone()
        };
        let mut receiver_lock = receiver.lock().await;
        receiver_lock
            .next()
            .await
            .expect("Reference to sender held")
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

**File:** src/protocol/echo_broadcast.rs (L241-263)
```rust
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

**File:** src/protocol/echo_broadcast.rs (L322-325)
```rust
                    // we can thus output that the n instances of the broadcast protocols have succeeded
                    if state.iter().all(|x| x.finish_ready) {
                        return Ok(vote_output);
                    }
```

**File:** src/dkg.rs (L362-362)
```rust
    let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;
```

**File:** src/dkg.rs (L422-426)
```rust
    for (from, their_commitment_hash) in
        recv_from_others(&chan, wait_round_1, &participants, me).await?
    {
        all_hash_commitments.put(from, their_commitment_hash);
    }
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

**File:** src/dkg.rs (L514-528)
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
```

**File:** src/dkg.rs (L531-531)
```rust
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```
