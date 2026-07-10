### Title
`Protocol::message()` Accepts Unvalidated `from` Participant, Causing Echo Broadcast to Abort DKG via Unhandled `InvalidIndex` Error — (`File: src/protocol/echo_broadcast.rs`)

---

### Summary

The `Protocol::message(from, data)` entry point accepts any `Participant` value as `from` without validating it against the protocol's participant list. When a message from a non-participant reaches the echo broadcast's `MessageType::Send` handler, the code calls `participants.index(from)?`, which returns `Err(ProtocolError::InvalidIndex)` for unknown participants. The `?` operator propagates this error, permanently aborting the DKG for the honest party. This is inconsistent with how `MessageType::Echo` and `MessageType::Ready` messages handle unknown senders (they use `ParticipantCounter::put`, which silently returns `false`).

---

### Finding Description

**Entry point — no sender validation in `Protocol::message()`:**

`src/protocol/mod.rs` line 64 defines the public API:

```rust
fn message(&mut self, from: Participant, data: MessageData);
```

The implementation in `src/protocol/internal.rs` lines 512–514 passes `from` directly into the message buffer with no check against the participant list:

```rust
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
```

`Comms::push_message` (lines 286–296) similarly performs no participant-list validation — it only checks message length and header format before calling `self.incoming.push(header, from, message)`.

The library's own test at lines 532–554 of `src/protocol/internal.rs` explicitly demonstrates this: an attacker can inject 512 messages for arbitrary waitpoints and they are all stored in the buffer without rejection.

**Root cause — crash on unknown sender in echo broadcast `Send` handler:**

In `src/protocol/echo_broadcast.rs` lines 193–209, the `MessageType::Send` branch calls:

```rust
if state_sid.finish_send || sid != participants.index(from)? {
    continue;
}
```

`participants.index(from)` returns `Err(ProtocolError::InvalidIndex)` when `from` is not in the participant list. The `?` propagates this error out of `reliable_broadcast_receive_all`, which propagates through `do_broadcast` in `src/dkg.rs` (line 435–441), permanently aborting the DKG for the honest party.

**Inconsistency with other message handlers:**

The `MessageType::Echo` handler (lines 212–264) and `MessageType::Ready` handler (lines 266–326) both use `state_sid.seen_echo.put(from)` / `state_sid.seen_ready.put(from)`, which call `ParticipantCounter::put`. That function (lines 310–326 of `src/participants.rs`) silently returns `false` for unknown participants — no error is propagated. Only the `Send` handler uses the error-propagating `participants.index(from)?` pattern.

**Attack path:**

1. The attacker is not in the DKG participant list.
2. Channel tags are deterministic and derived from public participant IDs via `ChannelTag::root_shared()` (lines 77–83 of `src/protocol/internal.rs`). Waitpoints are sequential starting from 0.
3. The attacker crafts a message with the correct `MessageHeader` (channel tag + waitpoint for the echo broadcast round) and a `MessageType::Send` payload.
4. The attacker calls `protocol.message(attacker_id, crafted_data)` — the library accepts it unconditionally.
5. The echo broadcast dequeues the message, evaluates `participants.index(attacker_id)?`, receives `Err(ProtocolError::InvalidIndex)`, and the DKG aborts permanently for the honest party.

---

### Impact Explanation

**High — Permanent denial of key generation for honest parties.**

A single injected `MessageType::Send` message from a non-participant at the correct channel tag and waitpoint causes the DKG to return an unrecoverable error for the targeted honest party. Since the attacker can repeat this for every DKG attempt, honest parties are permanently denied key generation. The same applies to reshare and refresh protocols that reuse the same echo broadcast infrastructure.

---

### Likelihood Explanation

**Medium.** The library's documented trust model assumes authenticated channels, but the library itself performs no enforcement of this assumption at the `Protocol::message()` boundary. Any application that delivers messages from non-participants (e.g., due to a missing allowlist check, a network-level injection, or a participant being removed mid-session) will trigger the crash. The library's own test (`attacker_can_fill_message_buffer_with_unused_waitpoints`) acknowledges that message injection is a realistic concern, yet the echo broadcast's `Send` handler is not hardened against it.

---

### Recommendation

Replace the error-propagating `participants.index(from)?` in the `MessageType::Send` handler with a graceful skip, consistent with how `Echo` and `Ready` messages handle unknown senders:

```rust
// Before (crashes on unknown sender):
if state_sid.finish_send || sid != participants.index(from)? {
    continue;
}

// After (gracefully ignores unknown sender):
let Ok(from_idx) = participants.index(from) else { continue; };
if state_sid.finish_send || sid != from_idx {
    continue;
}
```

Additionally, `Protocol::message()` should validate that `from` is a member of the protocol's participant list before enqueuing the message, providing defense-in-depth at the API boundary.

---

### Proof of Concept

```rust
// Honest DKG participants: [P0, P1, P2]
// Attacker: P99 (not in participant list)

// 1. Attacker computes the echo broadcast channel tag (deterministic, public):
//    ChannelTag::root_shared() -> child(waitpoint_for_broadcast_round)
// 2. Attacker crafts a MessageType::Send payload serialized with rmp_serde,
//    prefixed with the correct MessageHeader bytes.
// 3. Attacker calls:
protocol_of_honest_party.message(
    Participant::from(99u32),  // not in participant list
    crafted_send_message,      // valid header + MessageType::Send payload
);
// 4. On next poke(), the echo broadcast dequeues the message,
//    evaluates participants.index(Participant::from(99u32))
//    -> Err(ProtocolError::InvalidIndex)
//    -> DKG returns Err, honest party cannot complete key generation.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

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

**File:** src/protocol/internal.rs (L286-296)
```rust
    fn push_message(&self, from: Participant, message: MessageData) {
        if message.len() < MessageHeader::LEN {
            return;
        }

        let Some(header) = MessageHeader::from_bytes(&message) else {
            return;
        };

        self.incoming.push(header, from, message);
    }
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

**File:** src/protocol/echo_broadcast.rs (L191-209)
```rust
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
```

**File:** src/protocol/echo_broadcast.rs (L212-219)
```rust
            MessageType::Echo(data) => {
                // skip if I received echo message from the sender in a specific session (sid)
                // or if I had already passed to the ready phase in this same session
                if !state_sid.seen_echo.put(from) || state_sid.finish_echo {
                    continue;
                }
                // insert or increment the number of collected echo of a specific vote
                state_sid.data_echo.insert_or_increase_counter(data.clone());
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
