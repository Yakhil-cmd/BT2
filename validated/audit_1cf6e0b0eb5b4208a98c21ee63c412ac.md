### Title
Unbounded `MessageBuffer` Growth via Attacker-Controlled Waitpoints Enables Memory Exhaustion DoS - (File: src/protocol/internal.rs)

### Summary
The `MessageBuffer` inside `Comms` accumulates one `HashMap` entry and one unbounded `mpsc` channel per unique `MessageHeader` (channel tag + `u64` waitpoint). Because `Protocol::message()` accepts any well-formed 40-byte prefix as a valid header with no validation of the waitpoint value, a malicious participant can inject messages with arbitrary waitpoints, growing the buffer without bound and exhausting process memory. The codebase itself contains a test that explicitly confirms this attack succeeds.

### Finding Description
`MessageBuffer` is defined as a `HashMap<MessageHeader, SubMessageQueue>` with no capacity limit. [1](#0-0) 

`MessageHeader` is a 40-byte structure: a 32-byte `ChannelTag` plus an 8-byte `u64` waitpoint. [2](#0-1) 

`MessageHeader::from_bytes()` parses any 40-byte prefix as a valid header — the waitpoint field is accepted as any `u64` with no range check. [3](#0-2) 

`MessageBuffer::push()` calls `entry(header).or_default()` which creates a new `HashMap` entry **and** a new `futures::channel::mpsc::unbounded()` channel for every distinct header seen. [4](#0-3) 

`SubMessageQueue::Default` allocates an unbounded mpsc channel pair per entry. [5](#0-4) 

There is no eviction, size cap, or cleanup of stale entries anywhere in `MessageBuffer`. Entries inserted for waitpoints the honest protocol never polls remain in the `HashMap` for the entire lifetime of the `Comms` object.

The public entry point is `Protocol::message()`, implemented by `ProtocolExecutor`, which directly calls `Comms::push_message()` → `MessageBuffer::push()`. [6](#0-5) [7](#0-6) 

The developers themselves wrote a test that explicitly confirms the attack: [8](#0-7) 

The test name `attacker_can_fill_message_buffer_with_unused_waitpoints` and the assertion `messages.len() == attack_count` confirm that 512 injected messages for unused waitpoints all persist in the buffer with no mitigation.

### Impact Explanation
A malicious participant in any DKG, reshare, refresh, presign, sign, or CKD session can call `Protocol::message()` in a tight loop with messages whose first 40 bytes encode a valid channel tag and an incrementing `u64` waitpoint. Each call allocates a new `HashMap` entry plus an `mpsc` channel pair. With 2^64 possible waitpoints per channel tag, the attacker can exhaust all available process memory, crashing the honest node and permanently denying it the ability to complete or participate in any threshold operation. This matches **Medium: Griefing or resource-exhaustion by a malicious participant causing unbounded memory growth beyond documented behavior**.

### Likelihood Explanation
Any participant whose messages are delivered to an honest node's `Protocol::message()` can trigger this. No special privilege is required — the attacker only needs to be a recognized sender whose messages are forwarded by the network layer. The attack requires only crafting raw byte payloads with arbitrary waitpoint bytes, which is trivially achievable by any participant who controls their own message serialization.

### Recommendation
1. **Enforce a waitpoint allowlist**: Before inserting into `MessageBuffer`, validate that the incoming `(channel_tag, waitpoint)` pair corresponds to a waitpoint the honest protocol has already registered as expected. Maintain a set of "live" waitpoints and reject messages for unknown ones.
2. **Cap the buffer size**: Add a maximum entry count to `MessageBuffer` and drop (or return an error for) messages that would exceed it.
3. **Remove consumed entries**: After `pop()` drains a `SubMessageQueue` and the protocol advances past that waitpoint, remove the corresponding `HashMap` entry to reclaim memory.

### Proof of Concept
The existing test in the codebase is itself the proof of concept:

```rust
// src/protocol/internal.rs (lines 530-554)
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

    // All 512 entries persist — confirmed by the assertion:
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
```

In a real attack, replace `512` with a loop running until the process OOMs. Each iteration allocates one `HashMap` entry and one `mpsc` channel pair. The `Protocol::message()` public API is the delivery point; no authentication of the waitpoint value is performed. [9](#0-8)

### Citations

**File:** src/protocol/internal.rs (L130-136)
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Hash)]
struct MessageHeader {
    /// Identifying the channel.
    channel: ChannelTag,
    /// Identifying the specific waitpoint.
    waitpoint: Waitpoint,
}
```

**File:** src/protocol/internal.rs (L158-165)
```rust
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (data, _) = bytes.split_at_checked(Self::LEN)?;
        let (tag_part, wait_part) = data.split_at(ChannelTag::SIZE);
        Some(Self {
            channel: ChannelTag(tag_part.try_into().ok()?),
            waitpoint: u64::from_le_bytes(wait_part.try_into().ok()?),
        })
    }
```

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

**File:** src/protocol/internal.rs (L222-224)
```rust
struct MessageBuffer {
    messages: Arc<std::sync::Mutex<HashMap<MessageHeader, SubMessageQueue>>>,
}
```

**File:** src/protocol/internal.rs (L236-239)
```rust
    fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
        let mut messages_lock = self.messages.lock().expect("lock should not fail");
        messages_lock.entry(header).or_default().send(from, message);
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

**File:** src/protocol/mod.rs (L63-64)
```rust
    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
```
