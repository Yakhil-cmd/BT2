### Title
Unbounded Message Buffer Growth via Arbitrary Waitpoint Injection Enables Permanent DoS of DKG/Signing Protocols - (`src/protocol/internal.rs`)

---

### Summary

The `MessageBuffer` inside `Comms` accepts and stores messages for any `MessageHeader` (channel + waitpoint combination) without any bound on the number of distinct entries or the size of each queue. A malicious participant can inject messages with arbitrary, never-polled waitpoints, causing unbounded memory growth on honest nodes and permanently crashing DKG, reshare, refresh, and signing sessions.

---

### Finding Description

The protocol execution framework routes incoming messages through a `MessageBuffer` keyed by `MessageHeader` (a 32-byte channel tag + 8-byte waitpoint). The buffer is backed by an unbounded `HashMap<MessageHeader, SubMessageQueue>`, where each `SubMessageQueue` wraps a `futures::channel::mpsc::unbounded()` channel. [1](#0-0) 

The public entry point `Protocol::message()` feeds directly into `Comms::push_message`, which parses the header from the raw bytes and inserts the message into the map with no validation of the waitpoint value, no cap on the number of distinct headers, and no cap on the number of messages per queue: [2](#0-1) 

`SubMessageQueue` is created on demand for every new `MessageHeader` and uses an explicitly unbounded channel: [3](#0-2) 

The codebase itself contains a test that explicitly documents this attack surface, titled `attacker_can_fill_message_buffer_with_unused_waitpoints`. It injects 512 messages for waitpoints `1_000_000` through `1_000_511` — values the honest protocol code never polls — and asserts that all 512 entries are stored in the buffer: [4](#0-3) 

The `ProtocolExecutor::message()` implementation, which is the concrete implementation of the public `Protocol` trait's `message` method, passes every incoming message directly to `push_message` with no filtering: [5](#0-4) 

The honest protocol code only ever polls a small, fixed set of waitpoints (e.g., `wait_round_1`, `wait_round_3`, the broadcast waitpoint) determined by the protocol logic. Messages for any other waitpoint accumulate in the buffer forever and are never consumed.

---

### Impact Explanation

A malicious participant sends a continuous stream of messages with distinct, never-polled waitpoints to one or more honest nodes. Each message allocates a new `HashMap` entry and a new `SubMessageQueue` (with its sender/receiver pair). Memory grows without bound until the honest node's process is killed by the OS OOM killer or panics on allocation failure.

When an honest node crashes mid-protocol, the DKG, reshare, refresh, or signing session cannot complete. Because these protocols require all `n` participants to reach the final broadcast round, a single crashed honest node permanently blocks the session for all other participants. There is no recovery path within the protocol itself.

This matches the allowed impact: **Medium — Griefing or resource-exhaustion by a malicious participant causing unbounded memory growth beyond documented behavior, resulting in permanent denial of signing, key generation, reshare, or refresh for honest parties.**

---

### Likelihood Explanation

The `Protocol::message()` method is the documented public API for delivering network messages to a participant. Any participant in the protocol set — or any network relay that forwards messages — can call it with attacker-crafted payloads. The `MessageHeader` is parsed from the raw byte prefix of the message with no authentication or range check on the waitpoint field: [6](#0-5) 

A single malicious participant in a DKG or signing session can execute this attack at negligible cost: sending `k` distinct 40-byte headers (32-byte channel tag + 8-byte waitpoint) allocates `k` HashMap entries. No cryptographic material or protocol state is needed.

---

### Recommendation

1. **Cap the number of distinct `MessageHeader` entries** in `MessageBuffer`. Reject or drop messages once the map exceeds a bound proportional to `n × max_waitpoints_per_protocol`.
2. **Cap the queue depth per header** to a small constant (e.g., `n` messages), since honest participants send at most one message per waitpoint per round.
3. **Validate the waitpoint range** in `push_message`: reject messages whose waitpoint exceeds the maximum waitpoint the protocol will ever allocate for the current session.
4. **Authenticate the sender** before buffering: only buffer messages from participants in the known participant list.

---

### Proof of Concept

The existing test in the production source already demonstrates the attack:

```rust
// src/protocol/internal.rs, lines 532-554
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

    let messages = comms.incoming.messages.lock().expect("lock should not fail");
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
    // All 512 entries are stored; scaling to millions causes OOM.
}
``` [4](#0-3) 

To escalate to a full DoS: during a live DKG session, the malicious participant calls `protocol.message(attacker_id, crafted_bytes)` in a tight loop with incrementing waitpoint values. Each call inserts a new entry into the honest node's `MessageBuffer`. At ~200 bytes per entry (HashMap overhead + channel pair + message bytes), 5 million injected messages consume ~1 GB of memory, crashing the node before the DKG broadcast round completes. [7](#0-6)

### Citations

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
