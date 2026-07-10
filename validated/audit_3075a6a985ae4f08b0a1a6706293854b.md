### Title
Unbounded Memory Growth in `MessageBuffer` via Malicious Message Injection - (File: `src/protocol/internal.rs`)

### Summary
A malicious participant can inject an unlimited number of messages with arbitrary `MessageHeader` values into the `MessageBuffer` of any honest party's protocol instance. Because `push_message` applies no size cap to the internal `HashMap<MessageHeader, SubMessageQueue>`, and each `SubMessageQueue` is backed by an `mpsc::unbounded()` channel, memory grows without bound until the process is killed by the OS, permanently denying DKG, signing, reshare, refresh, and CKD for all honest parties sharing that process.

### Finding Description

`Comms::push_message` is the entry point for all inbound messages. It parses a `MessageHeader` from the raw bytes and inserts the message into `MessageBuffer.messages`:

```rust
// src/protocol/internal.rs:286-296
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

`MessageBuffer::push` then calls `or_default()` on the `HashMap`, creating a new `SubMessageQueue` for every previously-unseen `(channel, waitpoint)` pair:

```rust
// src/protocol/internal.rs:236-239
fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
    let mut messages_lock = self.messages.lock().expect("lock should not fail");
    messages_lock.entry(header).or_default().send(from, message);
}
```

`SubMessageQueue::default()` creates an `mpsc::unbounded()` channel, so both the number of `HashMap` keys and the depth of each queue are uncapped:

```rust
// src/protocol/internal.rs:204-212
impl Default for SubMessageQueue {
    fn default() -> Self {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        Self { sender, receiver: Arc::new(Mutex::new(receiver)) }
    }
}
```

The public `Protocol::message` method (line 512-514) is the caller-facing entry point that feeds directly into `push_message`, so any participant in the protocol can trigger this path.

The repository's own test suite explicitly documents and confirms this behavior:

```rust
// src/protocol/internal.rs:532-553
#[test]
fn attacker_can_fill_message_buffer_with_unused_waitpoints() {
    let comms = Comms::new();
    let attacker = Participant::from(99_u32);
    let attack_count = 512_u64;
    for i in 0..attack_count {
        let header = MessageHeader::new(ChannelTag::root_shared()).with_waitpoint(1_000_000 + i);
        let mut message = header.to_bytes().to_vec();
        message.extend_from_slice(&i.to_le_bytes());
        comms.push_message(attacker, message);
    }
    let messages = comms.incoming.messages.lock().expect("lock should not fail");
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
```

The test asserts that all 512 injected entries are present in the `HashMap` — confirming unbounded growth with no rejection or eviction.

### Impact Explanation

A single malicious participant can exhaust the memory of every honest party's process by flooding `Protocol::message` with well-formed bytes that encode arbitrary `MessageHeader` values (e.g., incrementing waitpoints or random channel tags). Because the `HashMap` and each `mpsc::unbounded` queue have no size limit, memory grows linearly with the number of injected messages. Once the process is OOM-killed, all in-progress DKG, reshare, refresh, presign, sign, and CKD sessions are permanently lost for all honest parties.

This matches: **Medium — Griefing or resource-exhaustion by a malicious caller or participant causing unbounded memory beyond documented behavior.**

The README documents that honest parties may wait indefinitely for missing messages, and places timeout responsibility on the caller. It does not document or accept that a peer can cause unbounded memory growth; that is a distinct and undocumented attack surface.

### Likelihood Explanation

Any participant in a running protocol session has direct access to `Protocol::message`. No special privilege, leaked key, or cryptographic break is required. The attacker only needs to send raw bytes with a valid `MessageHeader::LEN`-byte prefix encoding an arbitrary `(channel, waitpoint)` pair. The attack is trivially scriptable and requires no coordination.

### Recommendation

Apply a capacity bound to `MessageBuffer`. Two complementary mitigations:

1. **Cap the `HashMap` key count**: In `MessageBuffer::push`, reject (or evict) entries when `messages.len()` exceeds a protocol-derived limit (e.g., `n_participants × max_waitpoints`).
2. **Replace `mpsc::unbounded()` with `mpsc::channel(capacity)`**: Use a bounded channel per `SubMessageQueue` so that a single header cannot accumulate unlimited messages.

Additionally, remove or convert the existing test `attacker_can_fill_message_buffer_with_unused_waitpoints` from a documentation-of-known-behavior test into a regression test that asserts the attack is *rejected*.

### Proof of Concept

```rust
// Attacker's view: inject 1,000,000 messages with distinct waitpoints
// into an honest party's protocol instance during any DKG/sign session.
let honest_protocol: &mut dyn Protocol<Output = _> = ...;
let attacker_id = Participant::from(99_u32);

for i in 0u64..1_000_000 {
    // Craft a valid MessageHeader with an unused waitpoint
    let header = MessageHeader::new(ChannelTag::root_shared()).with_waitpoint(1_000_000 + i);
    let mut msg = header.to_bytes().to_vec();
    msg.extend_from_slice(&[0u8; 8]); // arbitrary payload
    // This is the public Protocol trait entry point
    honest_protocol.message(attacker_id, msg);
}
// honest_protocol's MessageBuffer now holds 1,000,000 HashMap entries,
// each backed by an unbounded mpsc queue. Process OOM follows.
```

**Root cause lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
