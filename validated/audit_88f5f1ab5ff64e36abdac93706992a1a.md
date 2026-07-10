### Title
Unbounded `MessageBuffer` Growth via Arbitrary Waitpoint Injection — (`File: src/protocol/internal.rs`)

### Summary

The `MessageBuffer` inside `Comms` is a `HashMap<MessageHeader, SubMessageQueue>` with no bound on the number of entries. Any caller of the public `Protocol::message(from, data)` API can inject messages with arbitrary `(channel, waitpoint)` headers, creating a new `SubMessageQueue` entry per unique header. Additionally, each `SubMessageQueue` uses `futures::channel::mpsc::unbounded()`, so even a single slot can accumulate unlimited messages. The developers themselves confirmed this attack surface in a test named `attacker_can_fill_message_buffer_with_unused_waitpoints`.

### Finding Description

**Root cause — two compounding layers:**

**Layer 1: Unbounded HashMap key space.**

`MessageBuffer` stores one `SubMessageQueue` per unique `MessageHeader`:

```rust
// src/protocol/internal.rs:222-224
struct MessageBuffer {
    messages: Arc<std::sync::Mutex<HashMap<MessageHeader, SubMessageQueue>>>,
}
```

`push` unconditionally inserts a new entry for every distinct header it receives:

```rust
// src/protocol/internal.rs:236-239
fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
    let mut messages_lock = self.messages.lock().expect("lock should not fail");
    messages_lock.entry(header).or_default().send(from, message);
}
```

A `MessageHeader` is a `(ChannelTag, Waitpoint)` pair where `Waitpoint = u64`, giving 2⁶⁴ distinct values per channel. There is no cap on how many entries the HashMap may hold.

**Layer 2: Unbounded per-slot queue.**

Each `SubMessageQueue` is backed by `futures::channel::mpsc::unbounded()`:

```rust
// src/protocol/internal.rs:204-212
impl Default for SubMessageQueue {
    fn default() -> Self {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        ...
    }
}
```

`send` calls `unbounded_send` with no backpressure:

```rust
// src/protocol/internal.rs:196-201
pub fn send(&self, from: Participant, message: MessageData) {
    self.sender
        .unbounded_send((from, message))
        .expect("unbound_send should not fail");
}
```

**Attacker-controlled entry path:**

The public `Protocol` trait exposes `message(from, data)` with no validation beyond a minimum length check and header parse:

```rust
// src/protocol/internal.rs:512-514
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
```

`push_message` only checks that the raw bytes are long enough to contain a header and that the header parses — it performs no allowlist check on the waitpoint value, no per-sender rate limit, and no total-size cap:

```rust
// src/protocol/internal.rs:286-296
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
```

A malicious participant constructs messages whose first 40 bytes encode a valid `(channel_tag, waitpoint)` pair with an arbitrary waitpoint value. By cycling through distinct waitpoints they create one new HashMap entry per message. The developers confirmed this is reachable and effective in a test that asserts 512 injected messages produce exactly 512 HashMap entries:

```rust
// src/protocol/internal.rs:530-554
fn attacker_can_fill_message_buffer_with_unused_waitpoints() {
    ...
    for i in 0..attack_count {
        let header = MessageHeader::new(ChannelTag::root_shared())
            .with_waitpoint(1_000_000 + i);
        ...
        comms.push_message(attacker, message);
    }
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
```

### Impact Explanation

A malicious participant floods an honest node's `MessageBuffer` with messages targeting unused waitpoints. Each message allocates a new `HashMap` entry plus an `UnboundedSender`/`UnboundedReceiver` pair. Sustained injection exhausts the honest node's heap, causing an OOM condition that terminates the process. This permanently denies the honest party the ability to complete any in-progress or future DKG, reshare, refresh, presign, sign, or CKD session.

**Matched allowed impact:** *Medium — Griefing or resource-exhaustion by a malicious caller or participant causing unbounded memory beyond documented behavior.*

The README documents that functions wait indefinitely for expected messages, and that callers are responsible for timeouts. It does not document or accept that a peer can cause unbounded memory growth as a side-effect of sending messages.

### Likelihood Explanation

Any participant in a running protocol session can call `Protocol::message()` — this is the normal, required API for delivering network messages. No special privilege is needed. The attacker only needs to be a registered participant (or any entity whose messages the orchestrating layer forwards). Crafting a valid header for an arbitrary waitpoint requires only knowledge of the 40-byte header format, which is deterministic and public. The attack is trivially scriptable and requires no cryptographic capability.

### Recommendation

1. **Cap the HashMap size.** Reject messages that would create a new entry when the HashMap already holds more than `K` entries (where `K` is a small multiple of the expected number of protocol rounds × participants).
2. **Allowlist valid waitpoints.** Track which waitpoints the protocol has actually allocated via `next_waitpoint()` and silently drop messages whose waitpoint is not in that set.
3. **Replace unbounded channels with bounded ones.** Use `futures::channel::mpsc::channel(capacity)` instead of `unbounded()` so that per-slot memory is capped.
4. **Per-sender rate limiting.** Track the number of buffered bytes or messages per `(from, header)` pair and drop excess.

### Proof of Concept

The repository's own test demonstrates the attack:

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
        // Attacker injects messages for waitpoints the honest code never polls.
        comms.push_message(attacker, message);
    }

    let messages = comms.incoming.messages.lock().unwrap();
    // 512 distinct HashMap entries created — one per injected waitpoint
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
```

Scale `attack_count` to millions (each message is ~48 bytes of raw data plus HashMap overhead plus two channel endpoints per entry) and the honest node's heap is exhausted, killing the process and permanently denying signing, DKG, reshare, refresh, and CKD for all honest parties sharing that session. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/protocol/mod.rs (L51-64)
```rust
pub trait Protocol {
    type Output;

    /// Poke the protocol, receiving a new action.
    ///
    /// The idea is that the protocol should be poked until it returns an error,
    /// or it returns an action with a return value, or it returns a wait action.
    ///
    /// Upon returning a wait action, that protocol will not advance any further
    /// until a new message arrives.
    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError>;

    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
```
