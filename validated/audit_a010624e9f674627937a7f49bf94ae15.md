### Title
Silent Message Drop in `Protocol::message()` Causes Permanent Protocol Hang — (File: `src/protocol/internal.rs`)

---

### Summary

The `push_message` function in `src/protocol/internal.rs` silently discards any incoming message shorter than `MessageHeader::LEN` (40 bytes) without returning an error or signaling the caller. Because `Protocol::message()` returns `()`, the integrator has no way to detect that a message was consumed but discarded. A malicious participant can exploit this by sending a sub-40-byte message in place of a valid protocol round message, causing every honest party waiting on that participant to block indefinitely inside `recv_from_others`. This permanently stalls DKG, ECDSA signing, FROST signing, and CKD for all honest parties.

---

### Finding Description

**Root cause — `push_message` silently drops short messages**

`src/protocol/internal.rs` lines 286–296:

```rust
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN {   // 40 bytes
        return;                               // ← silent drop, no error
    }
    let Some(header) = MessageHeader::from_bytes(&message) else {
        return;                               // ← silent drop, no error
    };
    self.incoming.push(header, from, message);
}
```

`MessageHeader::LEN = ChannelTag::SIZE + 8 = 32 + 8 = 40`.

Any `MessageData` shorter than 40 bytes is silently discarded. The function returns `()` with no indication of failure.

**Public API hides the drop**

`src/protocol/internal.rs` lines 512–514:

```rust
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
```

`Protocol::message()` is declared in `src/protocol/mod.rs` line 64 as `fn message(&mut self, from: Participant, data: MessageData)` — returning `()`. The integrator calling this function receives no signal that the message was dropped.

**Consequence — `recv_from_others` blocks forever**

`src/protocol/helpers.rs` lines 19–24:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;   // blocks until message arrives
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

`chan.recv(waitpoint)` ultimately calls `MessageBuffer::pop`, which awaits on an unbounded channel receiver with no timeout. If the message for a given `(channel_tag, waitpoint)` was silently dropped, no message will ever arrive for that slot, and the `await` never resolves. The protocol is permanently stuck.

**Scope of affected protocols**

`recv_from_others` is called in every protocol round across the entire library:
- `src/dkg.rs` — 3 call sites (key generation, reshare, refresh)
- `src/ecdsa/ot_based_ecdsa/triples/generation.rs` — 7 call sites (triple generation)
- `src/ecdsa/ot_based_ecdsa/presign.rs` — 3 call sites
- `src/ecdsa/ot_based_ecdsa/sign.rs` — 2 call sites
- `src/ecdsa/robust_ecdsa/presign.rs` — 2 call sites
- `src/ecdsa/robust_ecdsa/sign.rs` — 2 call sites
- `src/frost/eddsa/sign.rs` — 4 call sites
- `src/frost/redjubjub/sign.rs` — 2 call sites
- `src/confidential_key_derivation/protocol.rs` — 2 call sites

---

### Impact Explanation

A single malicious participant sending one message of fewer than 40 bytes permanently stalls every honest party waiting on that participant's contribution in the current protocol round. Because the library provides no timeout mechanism and `Protocol::message()` returns no error, the integrator cannot distinguish "message not yet received" from "message received but silently discarded." The protocol never advances past the blocked `recv_from_others` call, permanently denying key generation, signing, reshare, refresh, or CKD output to all honest parties.

This maps to: **High — Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

The attack requires only that a participant be a legitimate member of the protocol session (authenticated channel access is the only prerequisite, per `docs/network-layer.md`). The malicious participant sends one crafted message of length < 40 bytes instead of the expected round message and withholds the valid message. No cryptographic material, no key leakage, and no external compromise is needed. Any single colluding or compromised node in any session can trigger this.

---

### Recommendation

1. Change `Protocol::message()` to return `Result<(), ProtocolError>` so the integrator can detect and react to dropped messages.
2. In `push_message`, return an explicit error (e.g., `ProtocolError::DeserializationError`) instead of silently returning when `message.len() < MessageHeader::LEN`.
3. Alternatively, add a minimum-length guard at the `Protocol::message()` boundary and propagate the error upward, consistent with how the original `ParticleExchange` fix reverted on invalid `data.length`.

---

### Proof of Concept

```
Setup: DKG session with participants [A (honest), B (honest), C (malicious)].

1. Protocol starts. All parties call poke() and send round-1 messages.
2. C sends a 5-byte message to A instead of its valid round-1 commitment.
3. A's integrator calls protocol_A.message(C, vec![0u8; 5]).
4. push_message: 5 < 40 → silent return. Message discarded.
5. A's recv_from_others loops: seen = {A, B}, waiting for C.
6. chan.recv(wait_round_1).await → MessageBuffer::pop → awaits forever.
7. A's DKG protocol never completes. Key generation is permanently denied.
8. B also never receives A's output (A never progresses to later rounds).
9. The entire DKG session is permanently stalled for all honest parties.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/protocol/internal.rs (L138-140)
```rust
impl MessageHeader {
    /// The number of bytes in this encoding.
    const LEN: usize = ChannelTag::SIZE + 8;
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

**File:** src/protocol/helpers.rs (L19-24)
```rust
    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }
```

**File:** src/protocol/mod.rs (L63-64)
```rust
    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
```
