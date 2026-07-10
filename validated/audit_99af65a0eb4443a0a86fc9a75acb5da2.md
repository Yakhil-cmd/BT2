### Title
Unauthenticated Non-Participant Message Injection Permanently Aborts DKG via Echo Broadcast Error Propagation - (File: `src/protocol/echo_broadcast.rs`, `src/protocol/internal.rs`)

---

### Summary

The `Protocol::message()` entry point accepts messages from any `from: Participant` without validating membership in the expected participant set. Inside `do_broadcast()`, the echo broadcast processes incoming messages using `participants.index(from)?`, which propagates a hard `ProtocolError::InvalidIndex` (rather than silently skipping) when `from` is not in the participant list. An attacker who can call `protocol.message()` with a non-participant `from` ID and a correctly-crafted channel header can permanently abort DKG, reshare, or refresh for any honest party.

---

### Finding Description

**Entry point — no participant validation at the message boundary:**

`ProtocolExecutor::message()` in `src/protocol/internal.rs` unconditionally forwards every incoming message into the shared `Comms` buffer:

```rust
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);   // no participant-set check
}
``` [1](#0-0) 

`push_message` only validates the message length and parses the `MessageHeader`; it never checks whether `from` belongs to the protocol's participant list. [2](#0-1) 

**Root cause — hard error propagation in echo broadcast for unknown senders:**

`do_broadcast()` (used by every DKG, reshare, and refresh call) processes messages in a loop. For the `Send` message type it executes:

```rust
if state_sid.finish_send || sid != participants.index(from)? {
    continue;
}
``` [3](#0-2) 

`participants.index(from)` returns `Err(ProtocolError::InvalidIndex)` when `from` is absent from the participant list: [4](#0-3) 

The `?` operator propagates this error immediately out of `do_broadcast`, which propagates through `do_keyshare` / `do_reshare`, causing the async future to resolve to `Err(...)`. The `ProtocolExecutor` stores this result and returns it on the next `poke()` call, permanently terminating the protocol: [5](#0-4) 

**Contrast with the safe path — `recv_from_others` silently drops unknown senders:**

`recv_from_others` uses `ParticipantCounter::put()`, which returns `false` (not an error) for unknown participants, so those messages are silently ignored: [6](#0-5) [7](#0-6) 

The echo broadcast does not apply the same defensive pattern.

**Channel header is deterministic and publicly known:**

The shared channel always uses `root_shared()` — a fixed SHA-256 hash of a public domain string — as its channel tag: [8](#0-7) 

Waitpoints are a sequential counter starting at 0. The DKG consumes waitpoint 0 for `wait_round_1`, so `do_broadcast` begins at waitpoint 1. An attacker who knows the protocol structure (it is open-source) can compute the exact `MessageHeader` bytes needed to route a message into the echo broadcast's receive queue.

The existing test in the codebase explicitly confirms that an attacker can inject messages with arbitrary headers into the buffer: [9](#0-8) 

---

### Impact Explanation

**High — Permanent denial of key generation, reshare, and refresh for honest parties.**

Once the injected message causes `participants.index(from)?` to return `Err`, the error propagates through `do_broadcast` → `do_keyshare` → the protocol future. The `ProtocolExecutor` stores the error result and the future is dropped (`self.fut = None`). Every subsequent `poke()` call returns `Action::Return(Err(...))`. The DKG session is permanently dead; honest parties cannot recover without restarting the entire protocol from scratch. Because the attacker can repeat the injection at the start of every new attempt, they can maintain a permanent denial of key generation. [10](#0-9) 

---

### Likelihood Explanation

Any party that can deliver a network message to an honest participant's `Protocol::message()` call can trigger this. In a threshold protocol, participants are expected to receive messages from the network; the `message()` API is the documented way to deliver them. The channel tag and waitpoint sequence are fully deterministic and derivable from the open-source code. No cryptographic material or privileged access is required — only the ability to send one crafted message.

---

### Recommendation

Apply the same defensive pattern used in `recv_from_others`: replace the hard-error `participants.index(from)?` with a soft skip for unknown senders inside the echo broadcast loop:

```rust
// Before (aborts on unknown sender):
if state_sid.finish_send || sid != participants.index(from)? {
    continue;
}

// After (silently ignores unknown sender):
let Ok(from_idx) = participants.index(from) else { continue; };
if state_sid.finish_send || sid != from_idx {
    continue;
}
```

Apply the same fix to the `Echo` and `Ready` message arms wherever `participants.index(from)` is called with `?`. Additionally, consider adding a participant-set membership check at the `Protocol::message()` boundary so that non-participant messages are rejected before they reach any protocol logic. [11](#0-10) 

---

### Proof of Concept

```
1. Honest parties P1, P2, P3 start DKG. Each calls keygen(), obtaining a Protocol instance.

2. Attacker (not in {P1, P2, P3}) computes the MessageHeader for the echo broadcast's
   Send waitpoint:
     channel_tag = SHA-256(NEAR_CHANNEL_TAGS_DOMAIN || "root shared")  // root_shared()
     waitpoint   = 1  // waitpoint 0 consumed by wait_round_1; do_broadcast starts at 1
     header_bytes = channel_tag || waitpoint.to_le_bytes()

3. Attacker crafts a message:
     msg = header_bytes || rmp_serde::encode(MessageType::Send(arbitrary_data))

4. Attacker calls:
     p1_protocol.message(Participant::from(9999_u32), msg)
   where 9999 is not in the participant list.

5. The message is pushed into P1's incoming buffer under the echo broadcast's header.

6. When P1's echo broadcast loop processes this message, it executes:
     participants.index(Participant::from(9999_u32))?
   → Err(ProtocolError::InvalidIndex)
   → do_broadcast returns Err
   → do_keyshare returns Err
   → P1's DKG future resolves to Err

7. P1's next poke() returns Action::Return(Err(InvalidIndex)).
   P1's DKG is permanently aborted. Repeating for P2 and P3 denies the entire key
   generation session.
```

### Citations

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

**File:** src/protocol/internal.rs (L505-509)
```rust
            if let std::task::Poll::Ready(result) = fut.poll_unpin(&mut cx) {
                self.result = Some(result);
                self.fut = None;
            }
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

**File:** src/participants.rs (L135-140)
```rust
    pub fn index(&self, participant: Participant) -> Result<usize, ProtocolError> {
        self.indices
            .get(&participant)
            .copied()
            .ok_or(ProtocolError::InvalidIndex)
    }
```

**File:** src/participants.rs (L310-314)
```rust
    pub fn put(&mut self, participant: Participant) -> bool {
        let i = match self.participants.indices.get(&participant) {
            None => return false,
            Some(&i) => i,
        };
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
