### Title
Unbounded `MessageBuffer` HashMap Growth via Attacker-Crafted Message Headers — (`File: src/protocol/internal.rs`)

### Summary
The `MessageBuffer` data structure inside `src/protocol/internal.rs` stores incoming messages in an unbounded `HashMap<MessageHeader, SubMessageQueue>`. Because the public `Protocol::message` entry point accepts raw bytes from any participant and inserts them into this map without any cap on the number of distinct headers, a malicious participant can craft messages with arbitrary `MessageHeader` values (unique channel-tag or waitpoint bytes) and cause the map to grow without bound, exhausting the honest party's memory. The codebase itself contains a test that explicitly demonstrates this attack path.

---

### Finding Description

Every protocol participant exposes a `Protocol::message` method as its sole external message-ingestion interface:

```rust
// src/protocol/mod.rs:64
fn message(&mut self, from: Participant, data: MessageData);
```

The implementation in `ProtocolExecutor` forwards every call directly to `Comms::push_message`:

```rust
// src/protocol/internal.rs:512-514
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
```

`push_message` parses the first 40 bytes of the raw message as a `MessageHeader` (32-byte `ChannelTag` + 8-byte `Waitpoint`) and inserts it into the buffer:

```rust
// src/protocol/internal.rs:286-296
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
```

`MessageBuffer::push` uses `HashMap::entry(...).or_default()` with **no size limit**:

```rust
// src/protocol/internal.rs:236-239
fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
    let mut messages_lock = self.messages.lock().expect("lock should not fail");
    messages_lock.entry(header).or_default().send(from, message);
}
```

`SubMessageQueue` itself is backed by `futures::channel::mpsc::unbounded()`, so both the number of distinct headers (HashMap entries) and the number of messages per header are unbounded:

```rust
// src/protocol/internal.rs:190-212
struct SubMessageQueue {
    sender: futures::channel::mpsc::UnboundedSender<(Participant, MessageData)>,
    receiver: Arc<Mutex<futures::channel::mpsc::UnboundedReceiver<(Participant, MessageData)>>>,
}
impl Default for SubMessageQueue {
    fn default() -> Self {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        ...
    }
}
```

The codebase already contains a test that proves the attack is reachable and effective:

```rust
// src/protocol/internal.rs:532-554
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

The test asserts that all 512 injected entries are stored — confirming the unbounded growth.

---

### Impact Explanation

A malicious participant floods an honest party's `Protocol::message` with messages whose first 40 bytes encode distinct `MessageHeader` values (e.g., incrementing the `Waitpoint` field). Each unique header creates a new `HashMap` entry and a new `SubMessageQueue` (with its own heap-allocated unbounded channel). Sending `N` such messages allocates `O(N)` heap memory. At sufficient scale this exhausts the honest party's memory, crashing the process and permanently denying any in-progress or future `keygen`, `reshare`, `sign`, or `ckd` operation.

This matches: **Medium — Griefing or resource-exhaustion by a malicious participant causing unbounded memory beyond documented behavior.**

---

### Likelihood Explanation

The `Protocol::message` method is the standard, documented API for delivering network messages to a participant. Any participant in the protocol set — or any network-level relay — can call it with arbitrary bytes. No authentication or rate-limiting is applied before the bytes reach `push_message`. The attack requires only the ability to send messages to an honest party, which is a baseline capability of every protocol participant.

---

### Recommendation

1. **Cap the number of distinct headers** stored in `MessageBuffer`. Reject (or drop) messages whose header is not in a pre-computed allowlist of expected `(channel_tag, waitpoint)` pairs for the current protocol phase.
2. **Cap the queue depth per header**. Replace `futures::channel::mpsc::unbounded()` with a bounded channel (e.g., `futures::channel::mpsc::channel(MAX_QUEUE_DEPTH)`) and drop or error on overflow.
3. **Validate the sender** before buffering: reject messages from participants not in the session's `ParticipantList` before they reach `push_message`.

---

### Proof of Concept

The existing test in the repository at `src/protocol/internal.rs:532–554` is a direct proof of concept. To reproduce:

```rust
// Attacker sends 512 messages with distinct waitpoints (1_000_000 .. 1_000_512).
// Each message is ≥ 40 bytes and parses as a valid MessageHeader.
// After delivery, the MessageBuffer HashMap contains 512 entries — one per unique header.
// Scaling to millions of messages causes OOM on the honest party.
for i in 0..attack_count {
    let header = MessageHeader::new(ChannelTag::root_shared()).with_waitpoint(1_000_000 + i);
    let mut message = header.to_bytes().to_vec();
    message.extend_from_slice(&i.to_le_bytes());
    comms.push_message(attacker, message);  // Protocol::message entry point
}
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/protocol/internal.rs (L222-239)
```rust
struct MessageBuffer {
    messages: Arc<std::sync::Mutex<HashMap<MessageHeader, SubMessageQueue>>>,
}

impl MessageBuffer {
    fn new() -> Self {
        Self {
            messages: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Push a message into this buffer.
    ///
    /// We also need the header for the message, and the participant who sent it.
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

**File:** src/protocol/mod.rs (L62-64)
```rust

    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
```
