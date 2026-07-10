### Title
Unguarded `?` Propagation on `participants.index(from)` in `reliable_broadcast_receive_all` Aborts DKG/Reshare/Refresh for All Honest Parties — (File: `src/protocol/echo_broadcast.rs`)

---

### Summary

In `reliable_broadcast_receive_all`, the `MessageType::Send` branch calls `participants.index(from)?`, which propagates a hard error if the sender is not in the participant list. The `Echo` and `Ready` branches handle the same situation gracefully via `ParticipantCounter::put()`, which silently returns `false` for unknown senders. This asymmetry means any actor who can deliver a single `Send`-typed message attributed to a non-participant causes the entire broadcast protocol — and therefore DKG, reshare, and refresh — to abort for all honest parties.

---

### Finding Description

`reliable_broadcast_receive_all` runs `n` concurrent instances of the echo-broadcast protocol, one per participant session. Messages arrive via `chan.recv(wait)` and are dispatched on their `MessageType` variant.

For `Echo` and `Ready` messages the code uses `ParticipantCounter::put(from)`:

```rust
// Echo branch — src/protocol/echo_broadcast.rs:215
if !state_sid.seen_echo.put(from) || state_sid.finish_echo {
    continue;
}
```

`ParticipantCounter::put` returns `false` (and the loop `continue`s) whenever `from` is absent from the participant list. [1](#0-0) 

For `Send` messages the code takes a different path:

```rust
// Send branch — src/protocol/echo_broadcast.rs:199
if state_sid.finish_send || sid != participants.index(from)? {
    continue;
}
```

`participants.index(from)` returns `Err(ProtocolError::InvalidIndex)` when `from` is not in the list. The `?` operator propagates that error out of `reliable_broadcast_receive_all`, terminating the function with an error rather than silently skipping the message. [2](#0-1) 

The comment directly above this check reads:

> *"The second condition prevents a malicious party starting the protocol on behalf on somebody else"*

This is the intended authorization guard — verifying that the sender's claimed session-id matches their actual index in the participant list. The guard is correct in intent but implemented with `?` instead of a graceful `continue`, so an unauthorized sender causes a hard abort rather than a silent skip. [3](#0-2) 

`do_broadcast` wraps `reliable_broadcast_receive_all` and is called in three places inside `do_keyshare`: the session-ID exchange round, the commitment/proof-of-knowledge broadcast round, and the final `broadcast_success` round. An abort at any of these points terminates the entire DKG/reshare/refresh run. [4](#0-3) [5](#0-4) [6](#0-5) 

The library's own test suite explicitly demonstrates that the `Protocol::message()` entry point accepts messages from arbitrary `Participant` values — including those outside the participant list — without any prior filtering:

```rust
// src/protocol/internal.rs:532-554
fn attacker_can_fill_message_buffer_with_unused_waitpoints() {
    let comms = Comms::new();
    let attacker = Participant::from(99_u32);
    ...
    comms.push_message(attacker, message);
    ...
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
``` [7](#0-6) 

The `Protocol::message` implementation passes every incoming message directly to `push_message` with no participant-list validation:

```rust
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
``` [8](#0-7) 

---

### Impact Explanation

A single crafted `MessageType::Send` message attributed to any `Participant` value that is absent from the participant list — delivered through the standard `Protocol::message()` interface — causes `reliable_broadcast_receive_all` to return `Err(ProtocolError::InvalidIndex)`. Because `do_broadcast` is called at multiple mandatory synchronization points inside `do_keyshare`, this aborts DKG, reshare, and refresh for every honest party in the session. The session cannot produce a `KeygenOutput`; honest parties are permanently denied key generation under that session. This matches the allowed impact: **High — Permanent denial of key generation, reshare, or refresh for honest parties under valid protocol inputs**.

---

### Likelihood Explanation

The `Protocol::message()` trait method is the sole external interface for delivering network messages to a running protocol instance. The library imposes no requirement that callers pre-filter messages by participant list, and the existing test (`attacker_can_fill_message_buffer_with_unused_waitpoints`) confirms the design accepts arbitrary senders. Any application-layer component that forwards unauthenticated or weakly-authenticated network messages — or any malicious participant who can spoof a `from` field — can trigger the abort with a single message. The attack requires no cryptographic capability and no knowledge of secret material.

---

### Recommendation

Replace the `?` propagation with a graceful skip, consistent with how `Echo` and `Ready` branches handle unknown senders:

```rust
// Before (aborts on non-participant sender):
if state_sid.finish_send || sid != participants.index(from)? {
    continue;
}

// After (ignores non-participant sender):
let Ok(from_idx) = participants.index(from) else { continue; };
if state_sid.finish_send || sid != from_idx {
    continue;
}
```

This preserves the authorization intent (a sender may only claim the session-id that matches their own index) while eliminating the abort path for unknown senders.

---

### Proof of Concept

1. Honest parties `[P0, P1, P2]` start `do_keygen`, which calls `do_keyshare`, which calls `do_broadcast` → `reliable_broadcast_receive_all`.
2. An attacker constructs a raw message whose header encodes `waitpoint = wait_broadcast` and whose payload deserializes as `(sid=0, MessageType::Send(some_data))`.
3. The attacker delivers this message to any honest party's protocol instance via `Protocol::message(Participant::from(99u32), crafted_bytes)`, where `Participant(99)` is not in `[P0, P1, P2]`.
4. Inside `reliable_broadcast_receive_all`, `chan.recv(wait)` returns `(Participant(99), (0, Send(some_data)))`.
5. `state.get_mut(0)` succeeds (sid 0 is valid).
6. The `MessageType::Send` branch executes `participants.index(Participant(99))?` → `Err(InvalidIndex)` → the function returns `Err`, aborting `do_broadcast`, `do_keyshare`, and `do_keygen` for that honest party.
7. Repeated against all parties, the entire DKG session fails. [9](#0-8) [10](#0-9)

### Citations

**File:** src/participants.rs (L135-140)
```rust
    pub fn index(&self, participant: Participant) -> Result<usize, ProtocolError> {
        self.indices
            .get(&participant)
            .copied()
            .ok_or(ProtocolError::InvalidIndex)
    }
```

**File:** src/participants.rs (L310-326)
```rust
    pub fn put(&mut self, participant: Participant) -> bool {
        let i = match self.participants.indices.get(&participant) {
            None => return false,
            Some(&i) => i,
        };

        // Need the old value to be false.
        if let Some(seen_i) = self.seen.get_mut(i) {
            let inserted = !std::mem::replace(seen_i, true);
            if inserted {
                self.counter -= 1;
            }
            inserted
        } else {
            false
        }
    }
```

**File:** src/protocol/echo_broadcast.rs (L173-210)
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

        is_simulated_vote = false;

        let Some(state_sid) = state.get_mut(sid) else {
            continue;
        };

        match vote.clone() {
            // Receive send vote then echo to everybody
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

**File:** src/protocol/internal.rs (L512-514)
```rust
    fn message(&mut self, from: Participant, data: MessageData) {
        self.comms.push_message(from, data);
    }
```

**File:** src/protocol/internal.rs (L532-554)
```rust
    fn attacker_can_fill_message_buffer_with_unused_waitpoints() {
        let comms = Comms::new();
        let attacker = Participant::from(99_u32);
        let attack_count = 512_u64;

        for i in 0..attack_count {
            let header =
                MessageHeader::new(ChannelTag::root_shared()).with_waitpoint(1_000_000 + i);
            let mut message = header.to_bytes().to_vec();
            message.extend_from_slice(&i.to_le_bytes());

            // Attacker injects messages for waitpoints the honest code never polls.
            comms.push_message(attacker, message);
        }

        let messages = comms
            .incoming
            .messages
            .lock()
            .expect("lock should not fail");

        assert!(messages.len() == usize::try_from(attack_count).unwrap());
    }
```
