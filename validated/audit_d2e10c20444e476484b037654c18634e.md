### Title
Unbounded `MessageBuffer` Growth via Malicious Message Injection — (`File: src/protocol/internal.rs`)

---

### Summary

A malicious participant can send an unbounded number of messages with arbitrary `waitpoint` values (or arbitrary channel tags) to any honest party running a protocol. Each unique header causes `MessageBuffer::push` to create a new `SubMessageQueue` entry in an uncapped `HashMap`, consuming unbounded memory. The codebase itself contains a test that explicitly demonstrates this attack path.

---

### Finding Description

`ProtocolExecutor::message()` is the public entry point for delivering incoming network messages to a running protocol instance:

```rust
// src/protocol/internal.rs:512-514
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
```

`push_message` parses the header from the raw bytes and unconditionally inserts it into the buffer:

```rust
// src/protocol/internal.rs:286-296
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
```

`MessageBuffer::push` uses `or_default()` to create a new `SubMessageQueue` for every previously-unseen header:

```rust
// src/protocol/internal.rs:236-239
fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
    let mut messages_lock = self.messages.lock().expect("lock should not fail");
    messages_lock.entry(header).or_default().send(from, message);
}
```

`SubMessageQueue` is backed by `futures::channel::mpsc::unbounded()`, which has no capacity limit. The outer `HashMap<MessageHeader, SubMessageQueue>` also has no size cap. A `MessageHeader` is a 40-byte value (32-byte channel tag + 8-byte waitpoint), so an attacker can trivially enumerate millions of distinct headers by varying the `waitpoint` field alone.

The codebase itself contains a test that explicitly confirms this attack is reachable and effective:

```rust
// src/protocol/internal.rs:530-554
fn attacker_can_fill_message_buffer_with_unused_waitpoints() {
    let comms = Comms::new();
    let attacker = Participant::from(99_u32);
    let attack_count = 512_u64;
    for i in 0..attack_count {
        let header = MessageHeader::new(ChannelTag::root_shared())
            .with_waitpoint(1_000_000 + i);
        let mut message = header.to_bytes().to_vec();
        message.extend_from_slice(&i.to_le_bytes());
        comms.push_message(attacker, message);
    }
    let messages = comms.incoming.messages.lock().expect("lock should not fail");
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
```

The test asserts that 512 injected messages with distinct waitpoints produce 512 distinct `HashMap` entries — confirming unbounded growth with no rejection or eviction.

---

### Impact Explanation

A malicious participant who is a valid member of any protocol session (DKG, presign, sign, reshare, refresh, CKD) can call `message()` on an honest party's `ProtocolExecutor` with crafted payloads containing arbitrary waitpoints. Each call allocates a new `HashMap` entry and an unbounded MPSC channel. Sending millions of such messages exhausts the honest party's heap memory, causing an OOM crash or severe degradation. This permanently denies the honest party from completing any protocol round, matching the **Medium: Griefing or resource-exhaustion** impact class.

---

### Likelihood Explanation

Any participant in a threshold protocol session can send arbitrary messages to other participants — this is the normal network model. The `message()` method is the standard delivery interface and is called for every received network packet. No authentication of the `waitpoint` field is performed, and no per-sender rate limit or total buffer cap exists. The attack requires only the ability to send raw bytes to an honest party's protocol executor, which every session participant already has.

---

### Recommendation

1. **Cap the `HashMap` size**: Reject `push` calls when `messages.len()` exceeds a protocol-defined maximum (e.g., `n_participants × max_rounds`).
2. **Validate waitpoints on receipt**: Each protocol knows its own valid waitpoint range; messages with out-of-range waitpoints should be dropped before insertion.
3. **Cap per-header queue depth**: Limit the number of buffered messages per `(header, sender)` pair to prevent a single sender from filling one slot.
4. **Track per-sender message counts**: Enforce a per-sender budget across all headers to bound total memory attributable to any one participant.

---

### Proof of Concept

A malicious participant in any active protocol session constructs messages with the shared-channel root tag and sequentially incremented waitpoints:

```
header = root_shared_tag || waitpoint_as_le64
message = header_bytes || arbitrary_payload
```

Sending `k` such messages with distinct waitpoints causes the honest party's `MessageBuffer` to allocate `k` `HashMap` entries and `k` unbounded MPSC channels. With `k = 10_000_000`, this exhausts several gigabytes of heap on a typical node, confirmed by the existing test at `src/protocol/internal.rs:530–554` which already asserts that every injected message creates a distinct buffer entry. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/protocol/internal.rs (L204-212)
```rust
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
