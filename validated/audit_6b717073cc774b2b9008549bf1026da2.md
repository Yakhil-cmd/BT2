### Title
Unvalidated `from` Participant in Echo-Broadcast Causes Permanent DKG/Reshare/Refresh Abort - (`File: src/protocol/echo_broadcast.rs`)

### Summary

`reliable_broadcast_receive_all` propagates a hard error when it receives a `MessageType::Send` message whose `from` participant is not in the participant list. Because `Protocol::message` is a public function that accepts any `from: Participant` without validation, any caller that delivers a message attributed to an unknown participant permanently aborts the broadcast, and therefore permanently aborts every DKG, reshare, or refresh session that depends on it.

### Finding Description

The public `Protocol` trait exposes:

```rust
fn message(&mut self, from: Participant, data: MessageData);
``` [1](#0-0) 

This function accepts any `from: Participant` value without validation. Internally, `push_message` stores the message in the buffer keyed only by the `MessageHeader` parsed from the raw bytes, with no check that `from` belongs to the session's participant list:

```rust
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
``` [2](#0-1) 

When `reliable_broadcast_receive_all` later dequeues such a message and the vote type is `MessageType::Send`, it calls:

```rust
if state_sid.finish_send || sid != participants.index(from)? {
    continue;
}
``` [3](#0-2) 

`participants.index(from)` returns `Err(ProtocolError::InvalidIndex)` when `from` is absent from the list:

```rust
pub fn index(&self, participant: Participant) -> Result<usize, ProtocolError> {
    self.indices
        .get(&participant)
        .copied()
        .ok_or(ProtocolError::InvalidIndex)
}
``` [4](#0-3) 

The `?` operator propagates this error immediately, terminating `reliable_broadcast_receive_all` with a hard failure. This is **inconsistent** with how the `Echo` and `Ready` branches handle the same situation — they call `seen_echo.put(from)` / `seen_ready.put(from)`, which silently returns `false` for unknown participants and safely `continue`s:

```rust
MessageType::Echo(data) => {
    if !state_sid.seen_echo.put(from) || state_sid.finish_echo {
        continue;
    }
``` [5](#0-4) 

`do_broadcast` — which wraps `reliable_broadcast_receive_all` — is called multiple times inside `do_keyshare`, which implements DKG, reshare, and refresh:

```rust
let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;
``` [6](#0-5) 

```rust
let commitments_and_proofs_map = do_broadcast(
    &mut chan, &participants, me, (commitment, proof_of_knowledge),
).await?;
``` [7](#0-6) 

A single injected `MessageType::Send` message from an unknown participant, delivered to any honest party's protocol instance at any of these broadcast waitpoints, causes that party's DKG/reshare/refresh to return a permanent error. The codebase's own test explicitly confirms the injection path is reachable:

```rust
fn attacker_can_fill_message_buffer_with_unused_waitpoints() {
    // Attacker injects messages for waitpoints the honest code never polls.
    comms.push_message(attacker, message);
    ...
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
``` [8](#0-7) 

### Impact Explanation

A successful injection permanently aborts DKG, reshare, or refresh for every honest party whose protocol instance receives the crafted message. No key material is produced. The session cannot be resumed; a fresh session must be started. This matches the allowed impact: **High — Permanent denial of key generation, reshare, or refresh for honest parties under valid protocol inputs.**

### Likelihood Explanation

The `MessageHeader` format is fully deterministic and public: the shared-channel tag is `SHA-256(NEAR_CHANNEL_TAGS_DOMAIN || "root shared")` and the waitpoint is a sequential counter starting at 0. [9](#0-8) 

An attacker who can deliver any bytes to a victim's `Protocol::message` call (e.g., a malicious co-participant, a compromised relay, or an application layer that does not pre-filter senders) can:

1. Compute the correct `MessageHeader` bytes for the first broadcast waitpoint.
2. Append a msgpack-encoded `(sid, MessageType::Send(data))` payload where `sid < n`.
3. Call `victim_protocol.message(unknown_participant, crafted_bytes)`.

The `Protocol::message` signature does not return a `Result` and provides no rejection mechanism, so the library implicitly promises graceful handling of any input — a promise broken only in the `Send` branch of `reliable_broadcast_receive_all`.

### Recommendation

Replace the propagating `?` with a graceful `continue`, consistent with how `Echo` and `Ready` branches already handle unknown participants:

```rust
MessageType::Send(data) => {
    let Ok(expected_sid) = participants.index(from) else {
        continue; // unknown sender — ignore, do not abort
    };
    if state_sid.finish_send || sid != expected_sid {
        continue;
    }
    ...
}
```

Additionally, document in `Protocol::message` that callers are responsible for only delivering messages from participants in the session, or add an explicit participant-membership guard inside `push_message`.

### Proof of Concept

```rust
// Attacker knows: root_shared tag is deterministic, waitpoint 0 is the first broadcast.
let root_shared_tag = ChannelTag::root_shared(); // fixed SHA-256 value
let header = MessageHeader::new(root_shared_tag).with_waitpoint(0);
let mut crafted = header.to_bytes().to_vec();

// Payload: (sid=0, MessageType::Send(arbitrary_data)) — valid msgpack
let payload: (usize, MessageType<[u8; 32]>) = (0, MessageType::Send([0u8; 32]));
rmp_serde::encode::write(&mut crafted, &payload).unwrap();

// unknown_participant is NOT in the DKG participant list
let unknown = Participant::from(0xDEAD_u32);

// Deliver to any honest party's protocol instance
victim_protocol.message(unknown, crafted);

// Next poke() drives the future; reliable_broadcast_receive_all dequeues the
// message, hits `participants.index(unknown)?`, returns Err(InvalidIndex),
// and the DKG permanently fails for this party.
let result = victim_protocol.poke();
assert!(matches!(result, Err(ProtocolError::InvalidIndex)));
``` [10](#0-9) [2](#0-1)

### Citations

**File:** src/protocol/mod.rs (L63-64)
```rust
    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
```

**File:** src/protocol/internal.rs (L77-83)
```rust
    fn root_shared() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(NEAR_CHANNEL_TAGS_DOMAIN);
        hasher.update(b"root shared");
        let out = hasher.finalize().into();
        Self(out)
    }
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

**File:** src/protocol/echo_broadcast.rs (L212-216)
```rust
            MessageType::Echo(data) => {
                // skip if I received echo message from the sender in a specific session (sid)
                // or if I had already passed to the ready phase in this same session
                if !state_sid.seen_echo.put(from) || state_sid.finish_echo {
                    continue;
```

**File:** src/participants.rs (L135-140)
```rust
    pub fn index(&self, participant: Participant) -> Result<usize, ProtocolError> {
        self.indices
            .get(&participant)
            .copied()
            .ok_or(ProtocolError::InvalidIndex)
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
