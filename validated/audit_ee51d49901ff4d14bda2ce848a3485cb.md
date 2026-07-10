### Title
Unbounded `MessageBuffer` Growth via Malicious Waitpoint Injection Causes Memory Exhaustion for Honest Protocol Participants - (File: `src/protocol/internal.rs`)

---

### Summary

The `MessageBuffer` inside `Comms` uses an unbounded `HashMap<MessageHeader, SubMessageQueue>` with no cap on the number of entries or per-queue depth. A malicious participant can call `Protocol::message()` with crafted byte payloads that parse as valid `MessageHeader`s containing arbitrary `waitpoint` values. Each unique `(channel, waitpoint)` pair creates a new `SubMessageQueue` backed by an `UnboundedSender`/`UnboundedReceiver` pair. Because there is no eviction, deduplication by sender, or size limit anywhere in the ingestion path, a single malicious participant can exhaust the memory of every honest party running any threshold protocol session (DKG, reshare, refresh, sign, CKD).

---

### Finding Description

`MessageBuffer` is defined as:

```rust
struct MessageBuffer {
    messages: Arc<std::sync::Mutex<HashMap<MessageHeader, SubMessageQueue>>>,
}
``` [1](#0-0) 

Each `SubMessageQueue` wraps an `futures::channel::mpsc::unbounded()` channel:

```rust
let (sender, receiver) = futures::channel::mpsc::unbounded();
``` [2](#0-1) 

The ingestion path `Comms::push_message` performs only a length check and a header parse before unconditionally inserting into the map:

```rust
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
``` [3](#0-2) 

`MessageBuffer::push` then calls `entry(header).or_default()`, which allocates a fresh `SubMessageQueue` for every previously-unseen `MessageHeader`:

```rust
fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
    let mut messages_lock = self.messages.lock().expect("lock should not fail");
    messages_lock.entry(header).or_default().send(from, message);
}
``` [4](#0-3) 

`push_message` is called directly from the public `Protocol::message()` implementation on `ProtocolExecutor`:

```rust
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
``` [5](#0-4) 

A `MessageHeader` is 40 bytes: 32 bytes of `ChannelTag` followed by 8 bytes of `waitpoint` (a `u64`). An attacker who knows the shared-channel root tag (which is a deterministic constant derived from `NEAR_CHANNEL_TAGS_DOMAIN` and the string `"root shared"`) can craft messages with any of 2^64 distinct waitpoint values. Each unique value creates a new HashMap entry and a new OS-level allocation for the unbounded MPSC channel pair.

The codebase itself contains a test that explicitly proves this attack succeeds with zero resistance:

```rust
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
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
``` [6](#0-5) 

The test is named `attacker_can_fill_message_buffer_with_unused_waitpoints` and asserts the attack succeeds — confirming the vulnerability is a known, unmitigated condition in the production code path.

---

### Impact Explanation

Every honest participant running a threshold protocol (DKG, reshare, refresh, sign, CKD) holds a `ProtocolExecutor` whose `message()` method is the network ingestion point. A malicious co-participant can flood it with messages carrying novel waitpoint values, causing the `HashMap` to grow without bound and the process to exhaust available memory. This permanently denies the honest party the ability to complete any protocol round, satisfying the **Medium** impact tier: *Griefing or resource-exhaustion by a malicious participant causing unbounded memory beyond documented behavior*.

---

### Likelihood Explanation

Any registered participant in a threshold session can send raw `MessageData` to other participants' `Protocol::message()` entry points. The `ChannelTag` root value is deterministic and publicly derivable. Constructing a valid 40-byte header with an arbitrary waitpoint requires no secret knowledge. A single malicious participant among `n` is sufficient; the attack requires only network access to the honest party's message ingestion interface.

---

### Recommendation

1. **Cap the HashMap size**: Reject `push_message` calls once the number of distinct `MessageHeader` keys exceeds a protocol-specific bound (e.g., `max_participants × max_rounds × safety_factor`).
2. **Cap per-queue depth**: Replace `futures::channel::mpsc::unbounded()` with a bounded channel (e.g., `futures::channel::mpsc::channel(MAX_QUEUE_DEPTH)`) and drop or error on overflow.
3. **Authenticate before buffering**: Verify that the `from` participant is a member of the current session's `ParticipantList` before calling `push_message`, and that the `waitpoint` falls within the expected range for the current protocol phase.

---

### Proof of Concept

The existing test in `src/protocol/internal.rs` at line 532 is a self-contained proof of concept. To reproduce:

```rust
let comms = Comms::new();
let attacker = Participant::from(99_u32);
// Craft 512 messages with distinct waitpoints the honest code never polls.
for i in 0u64..512 {
    let header = MessageHeader::new(ChannelTag::root_shared()).with_waitpoint(1_000_000 + i);
    let mut message = header.to_bytes().to_vec();
    message.extend_from_slice(&i.to_le_bytes());
    comms.push_message(attacker, message);
}
// HashMap now has 512 entries, each holding an unbounded MPSC allocation.
// Scale i to u64::MAX for OOM.
``` [7](#0-6) 

Scaling `attack_count` to the millions (or continuously streaming messages) will exhaust process memory on any honest node running a DKG, signing, or CKD session, permanently denying protocol completion.

### Citations

**File:** src/protocol/internal.rs (L204-211)
```rust
impl Default for SubMessageQueue {
    fn default() -> Self {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        Self {
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
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
