### Title
Unauthenticated `from` Parameter in `Protocol::message()` Enables Participant Impersonation and DKG/Reshare Denial-of-Service — (File: `src/protocol/mod.rs`, `src/protocol/internal.rs`, `src/protocol/helpers.rs`)

---

### Summary

The `Protocol::message(from: Participant, data: MessageData)` public API accepts a caller-supplied `from` identity with no authentication. Because `recv_from_others` accepts only the **first** message from each participant and silently drops all subsequent ones, a malicious caller who injects a spoofed message with `from=X` before honest participant X's real message arrives will permanently displace X's contribution. This causes cryptographic verification to fail in later DKG rounds, aborting key generation, reshare, or refresh for all honest parties.

---

### Finding Description

The `Protocol` trait exposes `message()` as a public, unrestricted entry point:

```rust
// src/protocol/mod.rs line 64
fn message(&mut self, from: Participant, data: MessageData);
```

The concrete implementation in `ProtocolExecutor` forwards the caller-supplied `from` directly into the message buffer with no validation:

```rust
// src/protocol/internal.rs lines 512-514
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
```

`push_message` stores the message keyed by its header and the caller-supplied `from` value:

```rust
// src/protocol/internal.rs lines 286-296
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
```

The message consumer `recv_from_others` uses `ParticipantCounter::put` to accept exactly one message per participant:

```rust
// src/protocol/helpers.rs lines 19-24
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

`ParticipantCounter::put` returns `true` only the first time a given participant is seen, and `false` for all subsequent calls:

```rust
// src/participants.rs lines 310-326
pub fn put(&mut self, participant: Participant) -> bool {
    // ...
    let inserted = !std::mem::replace(seen_i, true);
    if inserted { self.counter -= 1; }
    inserted
}
```

**Attack sequence in DKG Round 1 (commitment hash collection):**

1. Attacker M calls `protocol_Y.message(from=X, data=fake_commitment_hash_message)` before honest participant X's real message arrives.
2. `recv_from_others` calls `seen.put(X)` → returns `true` → M's fake hash is stored for X.
3. X's real commitment hash message arrives; `seen.put(X)` returns `false` → X's real message is silently dropped.
4. In DKG Round 3, `verify_commitment_hash` computes `H(X's_real_commitment)` and compares it against M's stored fake hash:

```rust
// src/dkg.rs lines 229-235
fn verify_commitment_hash<C: Ciphersuite>(...) -> Result<(), ProtocolError> {
    let actual_commitment_hash = all_hash_commitments.index(participant)?;
    let commitment_hash = domain_separate_hash(..., &(&participant, &commitment, &session_id))?;
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
    Ok(())
}
```

5. The hash mismatch causes `ProtocolError::InvalidCommitmentHash` → `do_keyshare` returns an error → DKG aborts for all honest parties.

The same displacement applies to the private signing-share round (Round 4 of `do_keyshare`), where `recv_from_others` is used again to collect per-participant signing shares. A displaced share fails `validate_received_share`, also aborting the protocol.

The codebase itself acknowledges this attack surface in a test:

```rust
// src/protocol/internal.rs lines 532-554
fn attacker_can_fill_message_buffer_with_unused_waitpoints() {
    let comms = Comms::new();
    let attacker = Participant::from(99_u32);
    // Attacker injects messages for waitpoints the honest code never polls.
    comms.push_message(attacker, message);
    // ...
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
```

---

### Impact Explanation

**High — Permanent denial of key generation, reshare, or refresh for honest parties.**

A single malicious participant (or a network-level attacker who can deliver messages before honest parties) can abort any DKG, reshare, or refresh session by injecting one spoofed message per targeted participant per round. Because `recv_from_others` is a first-come-first-served gate with no retry or eviction, the displacement is permanent within that session. All honest parties receive `ProtocolError::InvalidCommitmentHash` (or `InvalidSecretShare`) and must restart from scratch, which is again vulnerable to the same attack.

---

### Likelihood Explanation

Any participant in the protocol can call `Protocol::message()` on another participant's instance. In a real deployment the application layer routes network messages by calling `message(from, data)`. Because the library provides no cryptographic binding between the `from` field and the message content, a malicious participant M can send a network packet to Y claiming `from=X`. If the application layer does not independently authenticate the sender (which the library neither requires nor provides tooling for), Y's application will call `protocol_Y.message(from=X, data=M_payload)`. The attack requires only that M's message arrives before X's — a timing advantage that is trivially achievable on any real network.

---

### Recommendation

Bind the sender identity to the message content cryptographically before the message enters the protocol. Concretely:

1. **Require authenticated transport**: Document and enforce that callers must authenticate the `from` field before calling `message()`. Add a note to the `Protocol` trait doc that `from` must be the cryptographically verified sender identity.
2. **Sign protocol messages**: Have each participant sign their outgoing `MessageData` with a long-term identity key. The `message()` implementation (or a wrapper) should verify the signature against the claimed `from` participant's public key before pushing to the buffer.
3. **Alternatively, use per-round MACs or session-bound commitments**: Tie each message to the session ID so that a replayed or spoofed message from a different session or participant is rejected before it can displace the real message.

---

### Proof of Concept

```
Participants: X (honest), Y (honest), M (malicious), all in a 3-of-3 DKG.

1. DKG starts. All parties call `do_keyshare`.
2. Round 1: each party broadcasts a commitment hash via `recv_from_others`.
3. M, before X sends its real commitment hash to Y, calls:
       protocol_Y.message(from=X, data=<valid-header || garbage_hash>)
4. Y's `recv_from_others` loop:
       seen.put(X) → true  → stores M's garbage hash for X
5. X's real commitment hash arrives at Y:
       seen.put(X) → false → dropped silently
6. Round 3: Y calls `verify_commitment_hash` for X:
       H(X's_real_commitment) ≠ M's_garbage_hash
       → ProtocolError::InvalidCommitmentHash
7. Y's `do_keyshare` returns Err. DKG aborted.
   M repeats for every session restart → permanent DoS.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** src/protocol/mod.rs (L63-64)
```rust
    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
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

**File:** src/protocol/helpers.rs (L19-24)
```rust
    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }
```

**File:** src/participants.rs (L310-326)
```rust
    pub fn put(&mut self, participant: Participant) -> bool {
        let i = match self.participants.indices.get(&participant) {
            None => return false,
            Some(&i) => i,
        };

        // Need the old value to be false.
        if let Some(seen_i) = self.seen.get_mut(i) {
            let inserted = !std::mem::replace(seen_i, true);
            if inserted {
                self.counter -= 1;
            }
            inserted
        } else {
            false
        }
    }
```

**File:** src/dkg.rs (L229-235)
```rust
    let actual_commitment_hash = all_hash_commitments.index(participant)?;
    let commitment_hash =
        domain_separate_hash(domain_separator, &(&participant, &commitment, &session_id))?;
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
    Ok(())
```
