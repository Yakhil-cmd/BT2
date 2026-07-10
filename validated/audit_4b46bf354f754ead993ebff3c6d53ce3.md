### Title
Unbounded `MessageBuffer` Growth via Arbitrary Waitpoint Injection Enables Memory Exhaustion — (`File: src/protocol/internal.rs`)

---

### Summary

The `Protocol::message()` entry point accepts raw bytes from any caller and routes them into an unbounded `HashMap<MessageHeader, SubMessageQueue>`. A malicious participant can craft messages with arbitrary `MessageHeader` values (varying the `waitpoint` field) that the honest protocol logic never consumes. Because neither the `HashMap` nor the underlying `futures::channel::mpsc::unbounded()` channels impose any capacity limit, the buffer grows without bound, exhausting process memory and permanently denying signing, DKG, or any other protocol operation for honest parties.

---

### Finding Description

The `Protocol` trait exposes a public `message()` method that the application layer calls to deliver incoming network messages: [1](#0-0) 

`ProtocolExecutor` implements this by forwarding directly to `Comms::push_message`: [2](#0-1) 

`push_message` performs only a length check and header parse — it does **not** validate whether `from` is a registered participant, nor does it bound the number of messages accepted: [3](#0-2) 

The parsed header is used as a key in a `HashMap<MessageHeader, SubMessageQueue>`. Each new unique `(channel, waitpoint)` pair creates a fresh entry: [4](#0-3) 

Each `SubMessageQueue` is backed by a `futures::channel::mpsc::unbounded()` channel — explicitly without capacity: [5](#0-4) 

A `MessageHeader` is 40 bytes: a 32-byte `ChannelTag` plus an 8-byte `waitpoint`. An attacker who knows (or guesses) the root shared channel tag can craft messages with arbitrary `waitpoint` values. The honest protocol only ever polls a small, fixed set of waitpoints; messages for all other waitpoints accumulate in the `HashMap` and are never drained.

The repository's own test suite explicitly demonstrates and confirms this attack path: [6](#0-5) 

The test is named `attacker_can_fill_message_buffer_with_unused_waitpoints` and asserts that after 512 injected messages the `HashMap` contains 512 entries — confirming unbounded growth with no mitigation in place.

---

### Impact Explanation

**Medium — Griefing / resource exhaustion causing unbounded memory growth.**

An attacker who can call `Protocol::message()` (i.e., any network peer or malicious co-participant) can continuously inject messages for unused waitpoints. The `HashMap` and the unbounded MPSC queues inside it grow without limit. This causes:

- **OOM / process termination** if the attacker sends enough messages, permanently halting DKG, reshare, refresh, presign, or signing for all honest parties sharing that protocol instance.
- **Severe latency / lock contention** even before OOM, because every `push` and `pop` acquires `messages_lock` over the entire `HashMap`.

No cryptographic material is leaked, but the denial of service is permanent for the affected protocol run.

---

### Likelihood Explanation

Any co-participant in a threshold protocol (or any network-level attacker who can inject bytes into the message delivery path) can trigger this. The `Protocol::message()` method is the documented public API for delivering messages; there is no authentication or rate-limiting layer inside the library. The `waitpoint` field is a plain `u64`, giving an attacker 2^64 distinct keys to inject. Likelihood is **high** for a malicious co-participant and **medium** for an external network attacker (who must know or brute-force the channel tag).

---

### Recommendation

1. **Cap the `HashMap` size**: Reject `push_message` calls once the number of distinct `MessageHeader` keys exceeds a protocol-specific bound (e.g., `n_rounds * n_participants`).
2. **Cap per-queue depth**: Replace `futures::channel::mpsc::unbounded()` with a bounded channel (`futures::channel::mpsc::channel(capacity)`) so that each queue can hold at most `n_participants` messages.
3. **Validate the sender**: Before inserting into the buffer, check that `from` is a member of the known participant list and reject messages from unknown senders.
4. **Validate the waitpoint range**: Reject messages whose `waitpoint` exceeds the maximum waitpoint the protocol will ever use.

---

### Proof of Concept

The repository's own test at `src/protocol/internal.rs:532–554` is a direct proof of concept. Concretely:

```rust
let comms = Comms::new();
let attacker = Participant::from(99_u32);

for i in 0..u64::MAX {                          // unbounded
    let header = MessageHeader::new(ChannelTag::root_shared())
        .with_waitpoint(1_000_000 + i);          // unused waitpoint
    let mut message = header.to_bytes().to_vec();
    message.extend_from_slice(&i.to_le_bytes());
    comms.push_message(attacker, message);       // no rejection
}
// HashMap now has u64::MAX entries; process OOMs
```

The attacker only needs to know `ChannelTag::root_shared()`, which is a deterministic SHA-256 hash of public constants and is therefore fully predictable by any participant. [7](#0-6)

### Citations

**File:** src/protocol/mod.rs (L62-64)
```rust

    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
```

**File:** src/protocol/internal.rs (L77-83)
```rust
    fn root_shared() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(NEAR_CHANNEL_TAGS_DOMAIN);
        hasher.update(b"root shared");
        let out = hasher.finalize().into();
        Self(out)
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
