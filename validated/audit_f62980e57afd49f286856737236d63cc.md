### Title
Unvalidated Sender in Echo Broadcast Propagates Fatal Error on Non-Participant Message, Aborting DKG/Reshare - (File: `src/protocol/echo_broadcast.rs`)

### Summary
The `reliable_broadcast_receive_all` function uses the `?` operator on `participants.index(from)` inside the `MessageType::Send` branch. If the `from` field of an incoming message is not in the participant list, this call returns `Err(ProtocolError::InvalidIndex)`, which the `?` operator propagates immediately, aborting the entire DKG, reshare, or refresh protocol. The public `Protocol::message()` API accepts any `from: Participant` without validation, giving any caller a direct path to trigger this abort. This is inconsistent with `recv_from_others`, which silently ignores messages from non-participants.

### Finding Description

**Root cause — `src/protocol/echo_broadcast.rs` line 199:**

```rust
MessageType::Send(data) => {
    if state_sid.finish_send || sid != participants.index(from)? {
        continue;
    }
```

`participants.index(from)` returns `Err(ProtocolError::InvalidIndex)` when `from` is absent from the participant list. The `?` operator propagates this error out of `reliable_broadcast_receive_all`, terminating the function with an error rather than continuing the loop.

**Entry point — `src/protocol/internal.rs` lines 512–514:**

```rust
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
```

`Protocol::message()` is the public API through which the host application delivers network messages. It performs no validation of `from` — any `Participant` value is accepted and buffered. The library's own test at lines 530–554 of the same file is named `attacker_can_fill_message_buffer_with_unused_waitpoints` and explicitly demonstrates that an attacker can inject arbitrary messages through this path.

**Contrast with `recv_from_others` — `src/protocol/helpers.rs` lines 19–23:**

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

`ParticipantCounter::put` returns `false` for any `from` not in the participant list, so the message is silently skipped. This is the correct defensive pattern. `reliable_broadcast_receive_all` does not follow it.

**Attack path:**

1. A DKG, reshare, or refresh session is in progress; `do_broadcast` is called from `do_keyshare` in `src/dkg.rs` (lines 362, 435, 531).
2. The attacker observes any outgoing `SendMany` message to learn the channel tag (fixed: `SHA256(NEAR_CHANNEL_TAGS_DOMAIN || "root shared")`) and the current waitpoint.
3. The attacker crafts a payload that MessagePack-deserializes as `(valid_sid: usize, MessageType::Send(data))` where `valid_sid < n`.
4. The attacker calls `protocol.message(non_participant, crafted_bytes)` on any honest node, where `non_participant` is any `Participant` value not in the session's participant list.
5. Inside `reliable_broadcast_receive_all`, the message is dequeued, `state.get_mut(valid_sid)` succeeds, the `MessageType::Send` branch is entered, and `participants.index(non_participant)?` returns `Err(ProtocolError::InvalidIndex)`.
6. The `?` propagates the error; `reliable_broadcast_receive_all` returns `Err`, `do_broadcast` returns `Err`, and `do_keyshare` returns `Err`, aborting the protocol for that node.
7. The attacker repeats on every retry, making key generation or resharing permanently unavailable.

### Impact Explanation

Any caller of the public `Protocol::message()` API — including a malicious participant, a malicious coordinator, or any entity that can inject a single network message — can abort an in-progress DKG, reshare, or refresh session on any honest node. Because the attack requires only one crafted message per session attempt and can be repeated indefinitely, it constitutes **permanent denial of key generation, reshare, and refresh** for honest parties. No cryptographic material is needed; only knowledge of the channel tag (fixed constant) and the current waitpoint (observable from any honest broadcast) is required.

### Likelihood Explanation

The channel tag is a deterministic constant derived from a public domain separator. The waitpoint is visible in every `SendMany` message emitted by honest participants. Crafting a valid MessagePack payload for `(usize, MessageType::Send(T))` is trivial. The `Protocol::message()` function is the standard delivery interface every integrator must call. A single malicious participant already present in the session, or any network-layer attacker able to inject one message, can trigger the abort.

### Recommendation

Replace the `?`-propagating call with a graceful skip, matching the pattern used in `recv_from_others`:

```rust
// In reliable_broadcast_receive_all, MessageType::Send branch
let Ok(from_idx) = participants.index(from) else { continue; };
if state_sid.finish_send || sid != from_idx {
    continue;
}
```

This ensures that messages from non-participants are silently discarded rather than causing a fatal protocol error, consistent with the defensive pattern already used in `recv_from_others`.

### Proof of Concept

```rust
// Pseudocode demonstrating the abort
let mut protocol = keygen(&participants, me, threshold, rng).unwrap();

// Attacker: craft a message for the echo-broadcast waitpoint
// Channel tag = SHA256(NEAR_CHANNEL_TAGS_DOMAIN || "root shared") — fixed constant
// Waitpoint = 0 (first waitpoint used by do_broadcast in do_keyshare)
let header = MessageHeader { channel: root_shared_tag(), waitpoint: 0 };
let sid: usize = 0; // any valid index < participants.len()
let payload = rmp_serde::encode::to_vec(&(sid, MessageType::Send(some_data))).unwrap();
let mut msg = header.to_bytes().to_vec();
msg.extend_from_slice(&payload);

// non_participant is any Participant not in the session list
let non_participant = Participant::from(9999u32);
protocol.message(non_participant, msg);

// Next poke() drives the future; reliable_broadcast_receive_all hits
// participants.index(non_participant)? → Err(InvalidIndex) → protocol aborts
let result = protocol.poke(); // returns Err(ProtocolError::InvalidIndex)
assert!(result.is_err()); // DKG permanently aborted for this node
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/protocol/echo_broadcast.rs (L191-210)
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
            }
```

**File:** src/protocol/internal.rs (L512-514)
```rust
    fn message(&mut self, from: Participant, data: MessageData) {
        self.comms.push_message(from, data);
    }
```

**File:** src/protocol/internal.rs (L530-554)
```rust
    #[test]
    #[allow(clippy::significant_drop_tightening)]
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
