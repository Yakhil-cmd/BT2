### Title
Unbounded `MessageBuffer` Growth via Attacker-Injected Arbitrary-Waitpoint Messages Enables Memory Exhaustion DoS Against Any Protocol Participant - (File: `src/protocol/internal.rs`)

### Summary
A malicious protocol participant can inject an unlimited number of messages addressed to arbitrary, never-polled `MessageHeader` keys into any honest participant's `MessageBuffer`. Because the buffer is backed by an unbounded `HashMap` with no capacity limit and each sub-queue uses `futures::channel::mpsc::unbounded()`, the attacker can grow the honest node's heap without bound until OOM kills the process, permanently denying DKG, signing, reshare, refresh, or CKD for that participant. The codebase itself contains a test that explicitly proves this behavior is reachable.

### Finding Description

The `MessageBuffer` struct in `src/protocol/internal.rs` stores incoming messages in a `HashMap<MessageHeader, SubMessageQueue>`. [1](#0-0) 

Each `SubMessageQueue` is created with `futures::channel::mpsc::unbounded()`, which imposes no memory cap. [2](#0-1) 

The public entry point `Protocol::message()` calls `Comms::push_message()`, which parses the first 40 bytes of any incoming byte slice as a `MessageHeader` and unconditionally inserts it into the buffer: [3](#0-2) 

A `MessageHeader` is a 32-byte `ChannelTag` plus an 8-byte `Waitpoint` (`u64`). The honest protocol only ever polls a small, fixed set of waitpoints per session. Any message whose header does not match a polled waitpoint is buffered forever and never consumed. There is no eviction, no capacity limit, and no per-sender quota.

The codebase itself contains a test that explicitly documents and proves this attack path: [4](#0-3) 

The test name is `attacker_can_fill_message_buffer_with_unused_waitpoints` and it asserts that 512 injected messages for unused waitpoints are all retained in the buffer — confirming the vulnerability is known but unfixed.

### Impact Explanation

An attacker who is a valid participant in any protocol session (DKG, signing, reshare, refresh, CKD) can call `Protocol::message(from, data)` on an honest participant's protocol instance with messages whose `MessageHeader` encodes arbitrary waitpoints (e.g., `1_000_000`, `1_000_001`, …, `u64::MAX`). Each distinct header creates a new `HashMap` entry. Each message body is stored in the per-header `UnboundedSender` queue. Since neither the `HashMap` nor the queues have any size bound, the honest participant's heap grows without limit. When the process is OOM-killed, that participant can never complete the in-progress DKG, signing, reshare, refresh, or CKD session. Because the private key material is distributed and the session cannot be resumed from the aborted state, this constitutes **permanent denial of signing/key generation/reshare/refresh/CKD for honest parties**.

This matches the allowed impact: **High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions.**

### Likelihood Explanation

Any participant in a protocol session can deliver messages to any other participant via the `Protocol::message()` API — this is the normal, documented mechanism for network message delivery. No privileged access, leaked keys, or cryptographic breaks are required. The attacker only needs to be a valid (possibly malicious) participant in the session. The attack is cheap: crafting messages with arbitrary waitpoints requires only constructing a 40-byte header prefix. The attacker can send millions of such messages before the honest participant's protocol makes any progress, since `message()` and `poke()` are driven by the library consumer in a single-threaded loop.

### Recommendation

1. **Cap the `MessageBuffer` size**: Enforce a maximum number of distinct `MessageHeader` keys in the `HashMap` (e.g., bounded by `n_participants × n_protocol_rounds × small_constant`). Reject or drop messages that would exceed this cap.
2. **Cap per-header queue depth**: Replace `futures::channel::mpsc::unbounded()` with `futures::channel::mpsc::channel(MAX_DEPTH)` to bound memory per waitpoint slot.
3. **Validate waitpoints on ingress**: Reject messages whose waitpoint value exceeds the maximum waitpoint the current protocol phase will ever poll. This requires exposing the current protocol phase's waitpoint range to the message ingress path.
4. **Per-sender quota**: Track how many buffered bytes each `Participant` has contributed and drop messages from participants that exceed a configurable limit.

### Proof of Concept

```rust
#[test]
fn malicious_participant_exhausts_message_buffer_memory() {
    use crate::protocol::internal::{Comms, ChannelTag, MessageHeader};
    use crate::participants::Participant;

    let comms = Comms::new();
    let attacker = Participant::from(99_u32);

    // Attacker sends messages for 10_000_000 distinct unused waitpoints.
    // Each creates a new HashMap entry + unbounded queue allocation.
    // In practice this is limited only by available RAM.
    for i in 0u64..10_000_000 {
        let header = MessageHeader::new(ChannelTag::root_shared())
            .with_waitpoint(1_000_000 + i);
        let mut message = header.to_bytes().to_vec();
        message.extend_from_slice(&i.to_le_bytes());
        // This is the public Protocol::message() entry point
        comms.push_message(attacker, message);
    }

    // All 10_000_000 entries are retained in the HashMap — no eviction.
    let messages = comms.incoming.messages.lock().unwrap();
    assert_eq!(messages.len(), 10_000_000);
    // Process is now near OOM; any honest DKG/sign/reshare session is dead.
}
```

The existing test `attacker_can_fill_message_buffer_with_unused_waitpoints` at `src/protocol/internal.rs:532–554` already proves the same root cause at smaller scale (512 entries) and explicitly names the attacker scenario in its test name, confirming this is a known, reachable, and currently unmitigated path. [5](#0-4) [1](#0-0) [3](#0-2) [6](#0-5) [4](#0-3)

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
