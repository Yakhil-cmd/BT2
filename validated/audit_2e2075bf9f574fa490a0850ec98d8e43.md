### Title
Permanent DKG/Reshare/Refresh Deadlock via Non-Sending Participant in `reliable_broadcast_receive_all` — (File: src/protocol/echo_broadcast.rs)

---

### Summary

The `reliable_broadcast_receive_all` function in `src/protocol/echo_broadcast.rs` contains an infinite loop that only exits when **all N** broadcast sessions have completed. A single malicious participant who never sends their `MessageType::Send` message causes the loop to block indefinitely on `chan.recv(wait).await` with no timeout, no abort path, and no escape hatch. Because the `Protocol` trait exposes no `abort()` method, honest parties are permanently stuck and cannot complete or restart DKG, reshare, or refresh operations.

---

### Finding Description

`reliable_broadcast_receive_all` runs N simultaneous instances of the echo-broadcast protocol — one per participant. The sole exit condition for the main loop is:

```rust
if state.iter().all(|x| x.finish_ready) {
    return Ok(vote_output);
}
``` [1](#0-0) 

`state[i].finish_ready` is set to `true` only after participant `i`'s session accumulates enough `Ready` votes, which in turn requires participant `i` to have first sent a `MessageType::Send` message:

```rust
MessageType::Send(data) => {
    if state_sid.finish_send || sid != participants.index(from)? {
        continue;
    }
    ...
    state_sid.finish_send = true;
``` [2](#0-1) 

If participant `i` never sends their `Send` message, `state[i].finish_send`, `state[i].finish_echo`, and `state[i].finish_ready` are never set. The loop blocks indefinitely on:

```rust
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,
};
``` [3](#0-2) 

There is no timeout, no per-session deadline, and no error path that fires when a participant is simply absent. The same structural issue exists in `recv_from_others`:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;
    ...
}
``` [4](#0-3) 

Both primitives are called throughout `do_keyshare`, the unified entry point for all key-lifecycle operations:

| Call site | Round | Blocking primitive |
|---|---|---|
| `do_broadcast` (session IDs) | Round 1 | `reliable_broadcast_receive_all` |
| `recv_from_others` (commitment hashes) | Round 2.9 | `recv_from_others` |
| `do_broadcast` (commitments + PoK) | Round 3 | `reliable_broadcast_receive_all` |
| `recv_from_others` (signing shares) | Round 4.6 | `recv_from_others` |
| `broadcast_success` | Round 5 | `reliable_broadcast_receive_all` | [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) 

The `Protocol` trait itself provides no `abort()` or cancellation method:

```rust
pub trait Protocol {
    type Output;
    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError>;
    fn message(&mut self, from: Participant, data: MessageData);
}
``` [10](#0-9) 

Once the future is stuck awaiting a message that never arrives, the `ProtocolExecutor` will return `Action::Wait` on every subsequent `poke()` call forever, with no mechanism for the caller to recover the session. [11](#0-10) 

---

### Impact Explanation

**High — Permanent denial of key generation, reshare, and refresh for honest parties.**

A single malicious participant can permanently block every honest party's DKG, reshare, or refresh session by simply not transmitting their broadcast message at any of the five blocking call sites. The honest parties' protocol futures never resolve, and because the `Protocol` trait has no abort path, the caller cannot recover without discarding the session entirely. Any new session that includes the same malicious participant will deadlock identically. This permanently denies the honest parties the ability to generate or rotate keys.

---

### Likelihood Explanation

Any registered participant in a DKG/reshare/refresh session can trigger this with zero cryptographic capability — they simply stop sending. No key material, no special privilege, and no prior compromise is required. The attacker can choose the most damaging moment (e.g., after all other participants have committed their shares in Round 4.6, maximising wasted work) and then go silent.

---

### Recommendation

1. **Add per-session timeouts** inside `reliable_broadcast_receive_all` and `recv_from_others`. After a configurable deadline, return a `ProtocolError` that identifies which participants failed to respond.
2. **Add an `abort()` or `cancel()` method to the `Protocol` trait** so callers can cleanly terminate a stuck session and free its resources.
3. **Track non-responsive participants** and surface them in the error so the coordinator can exclude them from the next attempt.

---

### Proof of Concept

1. Start a DKG session with N ≥ 2 participants, one of which is malicious.
2. The malicious participant sends their Round 1 session-ID broadcast normally (to appear cooperative).
3. In Round 3, `do_broadcast` calls `reliable_broadcast_receive_all`. The malicious participant never sends `MessageType::Send` for their own session slot (`sid == malicious_index`).
4. `state[malicious_index].finish_send` is never set; `state[malicious_index].finish_ready` remains `false`.
5. The exit condition `state.iter().all(|x| x.finish_ready)` is never satisfied.
6. The loop blocks indefinitely on `chan.recv(wait).await`; `poke()` returns `Action::Wait` forever.
7. `do_keygen` / `do_reshare` / `do_refresh` never return for any honest party.
8. The `Protocol` trait provides no way to abort; the session is permanently stuck.

### Citations

**File:** src/protocol/echo_broadcast.rs (L179-182)
```rust
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
```

**File:** src/protocol/echo_broadcast.rs (L193-210)
```rust
            MessageType::Send(data) => {
                // If the sender is not the one identified by the session id (sid)
                // or if the sender have already delivered a MessageType::Send message
                // then skip.
                // The second condition prevents a malicious party starting the protocol
                // on behalf on somebody else
                if state_sid.finish_send || sid != participants.index(from)? {
                    continue;
                }
                vote = MessageType::Echo(data);
                // upon receiving a send message, echo it
                chan.send_many(wait, &(&sid, &vote))?;
                state_sid.finish_send = true;

                // simulate an echo vote sent by me
                is_simulated_vote = true;
                from = me;
            }
```

**File:** src/protocol/echo_broadcast.rs (L323-325)
```rust
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

**File:** src/protocol/internal.rs (L477-509)
```rust
    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError> {
        let mut polled_once_already = false;
        loop {
            // If there's outgoing messages, request to send them.
            if let Some(outgoing) = self.comms.outgoing() {
                return Ok(match outgoing {
                    Message::Many(m) => Action::SendMany(m),
                    Message::Private(to, m) => Action::SendPrivate(to, m),
                });
            }
            // If we already have a return result, return it.
            if let Some(result) = self.result.take() {
                return Ok(Action::Return(result?));
            }
            // If this is the second iteration, we already polled the future and there's no
            // progress that can be made.
            if polled_once_already {
                return Ok(Action::Wait);
            }
            // If we don't have a future, this is an extraneous poke() call, so return Wait.
            let Some(fut) = self.fut.as_mut() else {
                return Ok(Action::Wait);
            };
            // Now poll the future. It may generate some more messages to send or a return value,
            // so go back and check all of those again.
            polled_once_already = true;
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            if let std::task::Poll::Ready(result) = fut.poll_unpin(&mut cx) {
                self.result = Some(result);
                self.fut = None;
            }
        }
```
