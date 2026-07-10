### Title
Unbounded Memory Growth via Malicious Participant Injecting Messages for Unused Waitpoints — (`File: src/protocol/internal.rs`)

### Summary

The `MessageBuffer` in `src/protocol/internal.rs` accepts and stores any inbound message whose bytes parse as a valid `MessageHeader`, regardless of whether the embedded waitpoint is one the honest protocol ever polls. A malicious participant can call `Protocol::message()` with crafted messages targeting arbitrary waitpoints, causing the internal `HashMap<MessageHeader, SubMessageQueue>` to grow without bound. Because messages for unused waitpoints are never consumed, memory accumulates indefinitely, enabling an OOM-based denial of signing, key generation, reshare, or any other protocol operation.

### Finding Description

**Root cause — `Comms::push_message`:** [1](#0-0) 

The only validation performed is that the raw byte slice is at least `MessageHeader::LEN` bytes long and that the first `MessageHeader::LEN` bytes parse into a `ChannelTag` + `Waitpoint`. No check is made against the set of waitpoints the running protocol actually uses.

**Storage — `MessageBuffer::push`:** [2](#0-1) 

Each distinct `MessageHeader` (channel × waitpoint) creates a new `HashMap` entry backed by an `UnboundedSender`/`UnboundedReceiver` pair. [3](#0-2) 

`futures::channel::mpsc::unbounded()` imposes no capacity limit. Messages queued for a waitpoint the protocol never polls are never drained.

**Attacker entry point — `Protocol::message`:** [4](#0-3) 

Every participant in the protocol can call `message()` on any other participant's `ProtocolExecutor`. A single malicious participant can therefore inject an unbounded stream of crafted messages.

**The codebase itself documents this attack surface:** [5](#0-4) 

The test `attacker_can_fill_message_buffer_with_unused_waitpoints` explicitly asserts that 512 messages for unused waitpoints are successfully stored — confirming the attack path is reachable and unmitigated.

**Attack flow:**

1. Malicious participant `M` is admitted to any protocol session (DKG, reshare, presign, sign, CKD).
2. `M` calls `Protocol::message(from=M, data=crafted_bytes)` on each honest participant's executor, where `crafted_bytes` encodes a valid `ChannelTag` (e.g., `ChannelTag::root_shared()`) paired with an arbitrary `Waitpoint` value (e.g., `1_000_000`, `1_000_001`, …).
3. Each unique `(channel, waitpoint)` pair inserts a new `HashMap` entry and enqueues the message on an unbounded channel.
4. Honest participants never poll those waitpoints, so the entries are never removed.
5. Repeated injection exhausts process memory, terminating the honest participant's process and permanently aborting the protocol session.

The `Waitpoint` type is `u64`, giving 2^64 distinct values per channel. Even at a modest injection rate the heap is exhausted long before the keyspace is explored.

### Impact Explanation

A single malicious participant — one who has been legitimately admitted to a threshold protocol session — can cause permanent denial of signing, key generation, reshare, refresh, or CKD for all honest parties in that session. The process terminates due to OOM; no protocol output is produced. This matches the allowed High impact: *"Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions."* It also fits the Medium band: *"Griefing or resource-exhaustion by a malicious caller or participant causing unbounded … memory … beyond documented behavior."*

### Likelihood Explanation

Any participant admitted to a session can execute this attack. No special privilege, leaked key, or cryptographic break is required. The crafted messages are trivially constructable: a valid `ChannelTag` is a public constant (`ChannelTag::root_shared()`) and the `Waitpoint` is an arbitrary `u64`. The attack is cheap (small messages, no computation) and can be launched immediately upon session start, before any honest protocol output is produced.

### Recommendation

1. **Cap the `MessageBuffer` size.** Enforce a maximum number of distinct `MessageHeader` keys (e.g., bounded by `n × max_waitpoints_per_protocol`) and drop or error on messages that would exceed the cap.
2. **Validate waitpoints against the protocol's expected range.** Before inserting into the buffer, check that the waitpoint falls within the range `[0, next_waitpoint)` for the relevant channel.
3. **Bound per-sender queue depth.** Track how many unprocessed messages each sender has contributed and reject further messages once a per-sender limit is reached.

### Proof of Concept

The existing test in the repository already demonstrates the attack:

```rust
// src/protocol/internal.rs (lines 532–554)
fn attacker_can_fill_message_buffer_with_unused_waitpoints() {
    let comms = Comms::new();
    let attacker = Participant::from(99_u32);
    let attack_count = 512_u64;

    for i in 0..attack_count {
        let header =
            MessageHeader::new(ChannelTag::root_shared()).with_waitpoint(1_000_000 + i);
        let mut message = header.to_bytes().to_vec();
        message.extend_from_slice(&i.to_le_bytes());
        comms.push_message(attacker, message);
    }

    let messages = comms.incoming.messages.lock().unwrap();
    // 512 distinct HashMap entries — all permanently resident, never drained
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
```

Scaling `attack_count` to the available address space (or running this in a loop across multiple sessions) exhausts process memory and terminates the honest participant, permanently denying any threshold protocol output.

### Citations

**File:** src/protocol/internal.rs (L190-212)
```rust
struct SubMessageQueue {
    sender: futures::channel::mpsc::UnboundedSender<(Participant, MessageData)>,
    receiver: Arc<Mutex<futures::channel::mpsc::UnboundedReceiver<(Participant, MessageData)>>>,
}

impl SubMessageQueue {
    pub fn send(&self, from: Participant, message: MessageData) {
        // This cannot fail because the receiver is also alive.
        self.sender
            .unbounded_send((from, message))
            .expect("unbound_send should not fail");
    }
}

impl Default for SubMessageQueue {
    fn default() -> Self {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        Self {
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }
}
```

**File:** src/protocol/internal.rs (L236-239)
```rust
    fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
        let mut messages_lock = self.messages.lock().expect("lock should not fail");
        messages_lock.entry(header).or_default().send(from, message);
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
