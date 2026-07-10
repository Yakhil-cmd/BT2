### Title
Unbounded `MessageBuffer` Growth via Attacker-Controlled Message Headers Causes Memory Exhaustion in All Protocol Instances - (File: `src/protocol/internal.rs`)

---

### Summary

The `MessageBuffer` inside `ProtocolExecutor` grows without bound when a malicious participant injects messages with arbitrary `MessageHeader` values. Because the public `Protocol::message()` API performs no validation of the header before buffering, an attacker can exhaust the memory of any honest participant running DKG, reshare, refresh, presign, sign, or CKD, permanently denying those operations.

---

### Finding Description

Every protocol in the library is backed by a `ProtocolExecutor<T>`, which holds a `Comms` struct containing an `incoming: MessageBuffer`. [1](#0-0) 

`MessageBuffer` is a `HashMap<MessageHeader, SubMessageQueue>`: [2](#0-1) 

Each `SubMessageQueue` is backed by `futures::channel::mpsc::unbounded()` — a channel with **no capacity limit**: [3](#0-2) 

When `MessageBuffer::push` is called, it calls `entry(header).or_default()`, which silently creates a new `SubMessageQueue` for every previously-unseen `MessageHeader`: [4](#0-3) 

The public `Protocol::message()` implementation on `ProtocolExecutor` calls `push_message` directly: [5](#0-4) 

`push_message` only checks that the raw byte slice is long enough to parse a `MessageHeader` (40 bytes). It performs **no validation** that the header corresponds to a legitimate protocol waitpoint or channel: [6](#0-5) 

A `MessageHeader` encodes a 32-byte `ChannelTag` and an 8-byte `waitpoint` (u64): [7](#0-6) 

An attacker who can call `message()` on a victim's protocol instance — which is the normal operating mode for any participant in the protocol — can craft messages with distinct `waitpoint` values (up to 2^64) or distinct `channel` values, each causing a new `HashMap` entry and a new unbounded channel to be allocated.

The codebase itself contains a test that **explicitly confirms and demonstrates** this attack: [8](#0-7) 

The test is named `attacker_can_fill_message_buffer_with_unused_waitpoints` and asserts that 512 distinct HashMap entries are created by injecting 512 messages with distinct waitpoints. This is a documented known-reachable path, not a theoretical concern.

---

### Impact Explanation

Every honest participant running any protocol (DKG via `do_keygen`/`do_reshare`, presign, sign, CKD) holds a `ProtocolExecutor` with this unbounded `MessageBuffer`. A malicious co-participant floods the victim's `message()` call with messages whose headers reference unused waitpoints. Each message allocates a new `HashMap` entry and enqueues into an unbounded channel. With a u64 waitpoint space, the attacker can sustain this indefinitely, growing the victim's heap until OOM, which terminates the process and permanently denies DKG, reshare, refresh, presign, sign, or CKD for that honest party.

This matches the allowed impact:
> **Medium: Griefing or resource-exhaustion by a malicious caller or participant causing unbounded CPU, memory, bandwidth, or non-terminating work beyond documented behavior**

---

### Likelihood Explanation

- The `Protocol::message()` function is the **standard public API** entry point; every participant in the protocol calls it on every other participant's instance as part of normal message delivery.
- No authentication or header validation is required before calling `message()`.
- The attack requires only that the attacker be a co-participant (or any entity that can inject messages into the routing layer), which is the normal threat model for threshold protocols.
- The attack is trivially cheap: sending raw byte vectors with incrementing 8-byte waitpoint fields requires no cryptographic work.

---

### Recommendation

Apply one or both of the following mitigations:

1. **Bound the HashMap size**: Before inserting a new entry in `MessageBuffer::push`, check that the number of distinct headers does not exceed a protocol-defined maximum (e.g., `max_participants * max_rounds`). Reject or drop messages that would exceed this bound.

2. **Bound the per-header queue depth**: Replace `futures::channel::mpsc::unbounded()` with `futures::channel::mpsc::channel(capacity)` using a small fixed capacity (e.g., `N` where `N` is the participant count), so that a single sender cannot enqueue more than `N` messages per waitpoint.

3. **Validate headers against known waitpoints**: Track which waitpoints have been allocated via `next_waitpoint()` and silently drop messages whose headers reference unallocated waitpoints.

---

### Proof of Concept

The existing test in the repository already demonstrates the attack. An attacker controlling a `Participant` in any live protocol session calls `protocol.message(attacker, crafted_bytes)` in a loop, varying the 8-byte waitpoint field at bytes `[32..40]` of the message:

```rust
// Analogous to the existing test at src/protocol/internal.rs:532-554
let comms = Comms::new();
let attacker = Participant::from(99_u32);

for i in 0_u64.. {  // unbounded — runs until OOM
    let header = MessageHeader::new(ChannelTag::root_shared()).with_waitpoint(1_000_000 + i);
    let mut message = header.to_bytes().to_vec();
    message.extend_from_slice(&i.to_le_bytes());
    comms.push_message(attacker, message);
    // Each iteration: +1 HashMap entry, +1 unbounded channel, +heap allocation
}
```

The repository's own test asserts that 512 such entries are created successfully with no error or bound check, confirming the root cause is reachable and unmitigated. [8](#0-7)

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

**File:** src/protocol/internal.rs (L267-271)
```rust
#[derive(Clone)]
pub struct Comms {
    incoming: MessageBuffer,
    outgoing: Arc<std::sync::Mutex<VecDeque<Message>>>,
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
