### Title
Unbounded `MessageBuffer` Growth via Malicious Message Injection — (`src/protocol/internal.rs`)

### Summary
The `Protocol::message()` entry point feeds all incoming bytes directly into an unbounded `MessageBuffer` backed by an unbounded `HashMap` and unbounded MPSC channels. A malicious participant can craft messages with arbitrary `MessageHeader` values (channel tag + waitpoint) and call `message()` repeatedly, growing the buffer without limit. The codebase's own test `attacker_can_fill_message_buffer_with_unused_waitpoints` explicitly confirms and demonstrates this behavior.

### Finding Description

`ProtocolExecutor::message()` is the sole external entry point for delivering network messages to any running protocol instance (DKG, presign, sign, CKD, etc.). [1](#0-0) 

It calls `Comms::push_message()`, which parses the first 40 bytes of any incoming byte slice as a `MessageHeader` (32-byte `ChannelTag` + 8-byte `Waitpoint`) and inserts the message into the buffer under that header key: [2](#0-1) 

The buffer is a `HashMap<MessageHeader, SubMessageQueue>` with no capacity bound: [3](#0-2) 

Each `SubMessageQueue` is backed by `futures::channel::mpsc::unbounded()`, which also has no capacity bound: [4](#0-3) 

An attacker who can call `message()` on a victim's protocol instance (i.e., any network peer who can send bytes to the honest party's protocol runner) can craft messages with distinct, never-polled `MessageHeader` values. Each unique header creates a new `HashMap` entry; each repeated header grows the corresponding unbounded MPSC queue. Neither path is bounded.

The codebase's own test confirms this is reachable and unmitigated: [5](#0-4) 

The test asserts `messages.len() == 512` after 512 injections — confirming all entries are retained in memory with no eviction or cap.

### Impact Explanation

Any honest party running DKG, reshare, refresh, presign, sign, or CKD is exposed. A malicious co-participant (or any network peer whose messages reach the protocol runner) can exhaust the honest party's heap memory by injecting messages with distinct crafted headers at high rate. This causes OOM termination of the honest party's process, permanently denying it the ability to complete the protocol. Because the `HashMap` grows proportionally to the number of distinct headers injected, the attacker's cost is O(N) messages while the victim's memory cost is also O(N) with no upper bound.

**Allowed impact matched:** Medium — Griefing or resource-exhaustion by a malicious participant causing unbounded memory beyond documented behavior.

### Likelihood Explanation

The `Protocol::message()` function is the standard, documented API that every protocol orchestrator must call for every received network message. Any participant in a DKG/sign/CKD session can send bytes to any other participant (authenticated channels are assumed, but authentication does not prevent a legitimate-but-malicious participant from sending garbage). The attack requires no cryptographic capability — only the ability to send raw bytes to the victim's protocol runner, which every co-participant already has.

### Recommendation

Apply a pull-pattern analog: validate incoming message headers against the set of currently-expected waitpoints before buffering. Concretely:

- Maintain a bounded set of "live" `MessageHeader` keys (those for which the protocol has issued a `recv` call but not yet consumed a message).
- In `push_message`, silently drop any message whose header is not in the live set, or cap the per-header queue depth (e.g., one message per `(from, header)` pair, since honest parties send at most one message per waitpoint).
- Alternatively, cap the total `HashMap` size and drop or error on overflow.

### Proof of Concept

The existing test in `src/protocol/internal.rs` is a direct proof of concept:

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

    let messages = comms.incoming.messages.lock().unwrap();
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
    // All 512 entries are retained — no eviction, no cap.
}
```

To escalate to OOM: replace `512` with an arbitrarily large count and run against a live DKG session. Each injected message with a unique waitpoint (e.g., `1_000_000 + i` for `i` in `0..u64::MAX`) creates a new `HashMap` entry, growing heap until the process is killed. [5](#0-4)

### Citations

**File:** src/protocol/internal.rs (L190-211)
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
