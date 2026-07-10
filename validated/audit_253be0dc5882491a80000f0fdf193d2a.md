### Title
Unauthenticated `from` Field in `Protocol::message()` Enables Sender Spoofing to Permanently Deny DKG/Key Generation — (File: `src/protocol/helpers.rs`, `src/protocol/internal.rs`)

---

### Summary

The `Protocol::message(from, data)` entry point is fully permissionless and accepts a caller-controlled `from: Participant` field with no authentication. The `recv_from_others` helper accepts the **first** message from each participant and silently drops all subsequent ones. A malicious coordinator or participant can therefore inject a spoofed message attributed to an honest participant before that participant's real message arrives, causing the honest participant's real message to be permanently discarded. In DKG this corrupts the commitment-hash binding established in Round 1, causing `verify_commitment_hash` to abort the protocol for all honest parties.

---

### Finding Description

**Step 1 — Permissionless, unauthenticated message injection**

`Protocol::message` is the sole inbound path for all protocol messages. Its implementation in `ProtocolExecutor` forwards the caller-supplied `from` directly into the message buffer with no validation:

```rust
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);   // from is fully caller-controlled
}
``` [1](#0-0) 

`push_message` performs only a length check and header parse; it never verifies that `from` matches any identity embedded in `data`:

```rust
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
``` [2](#0-1) 

**Step 2 — First-message-wins deduplication in `recv_from_others`**

Every multi-party round in DKG and signing uses `recv_from_others`, which marks a participant as *seen* on the first message and silently drops all later ones:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;
    if seen.put(from) {          // returns false (drop) if already seen
        messages.push((from, msg));
    }
}
``` [3](#0-2) 

**Step 3 — DKG commitment-hash binding is broken**

In `do_keyshare`, Round 1 collects a commitment hash from every participant via `recv_from_others` and stores it keyed by `from`:

```rust
for (from, their_commitment_hash) in
    recv_from_others(&chan, wait_round_1, &participants, me).await?
{
    all_hash_commitments.put(from, their_commitment_hash);
}
``` [4](#0-3) 

Round 3 then verifies that the commitment broadcast by each participant hashes to the value stored in Round 1:

```rust
verify_commitment_hash(
    &session_id, p,
    &mut commit_domain_separator.clone(),
    commitment_i,
    &all_hash_commitments,
)?;
``` [5](#0-4) 

If the Round 1 hash stored for participant B was injected by an attacker (and therefore does not match B's real commitment), `verify_commitment_hash` returns `ProtocolError::InvalidCommitmentHash` and the entire DKG aborts. [6](#0-5) 

---

### Impact Explanation

A malicious coordinator (or any party that can call `Protocol::message` on behalf of another participant) can permanently abort DKG, reshare, or refresh for all honest parties by injecting one spoofed Round-1 message per target participant. The same mechanism applies to the secret-share delivery round (`wait_round_3`): a spoofed share that fails `validate_received_share` also aborts the protocol.

This matches: **High — Permanent denial of key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

The `Protocol` trait is the public API surface. Any application that routes messages through an unauthenticated channel (e.g., a coordinator that relays messages without per-message signatures) exposes this path. The library provides no built-in mechanism to authenticate `from`, and the documentation does not warn callers that they must do so. A malicious coordinator, a compromised relay, or a participant who can observe and race honest messages can trigger the attack with a single injected message per round.

---

### Recommendation

1. **Document the authentication requirement explicitly** on `Protocol::message`: callers must guarantee that `from` is cryptographically authenticated before passing it to the library.
2. **Embed sender identity inside the signed message payload** so the protocol can cross-check `from` against the identity extracted from the message itself, removing reliance on the transport layer.
3. **Alternatively**, add an optional `verify_sender` hook to `Protocol` that the application can supply, allowing the library to reject messages whose `from` does not match an application-level signature.

---

### Proof of Concept

```
Participants: A (honest), B (honest), M (malicious coordinator)

1. DKG Round 1 begins. A, B, M each compute their commitment hash.
2. M calls protocol_A.message(from=B, data=fake_commitment_hash_for_B)
   before B's real Round-1 message is delivered to A.
3. recv_from_others on A marks B as seen; fake hash is stored:
       all_hash_commitments[B] = fake_commitment_hash_for_B
4. B's real Round-1 message arrives; seen.put(B) returns false → dropped.
5. DKG Round 3: B broadcasts its real commitment.
6. verify_commitment_hash(B, real_commitment, all_hash_commitments)
       → H(real_commitment) ≠ fake_commitment_hash_for_B
       → returns ProtocolError::InvalidCommitmentHash
7. DKG aborts for A (and all other honest parties who received the
   spoofed hash), permanently denying key generation.
``` [7](#0-6) [1](#0-0)

### Citations

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

**File:** src/dkg.rs (L228-236)
```rust
) -> Result<(), ProtocolError> {
    let actual_commitment_hash = all_hash_commitments.index(participant)?;
    let commitment_hash =
        domain_separate_hash(domain_separator, &(&participant, &commitment, &session_id))?;
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
    Ok(())
}
```

**File:** src/dkg.rs (L422-426)
```rust
    for (from, their_commitment_hash) in
        recv_from_others(&chan, wait_round_1, &participants, me).await?
    {
        all_hash_commitments.put(from, their_commitment_hash);
    }
```

**File:** src/dkg.rs (L463-469)
```rust
        verify_commitment_hash(
            &session_id,
            p,
            &mut commit_domain_separator.clone(), // you want to have the same state
            commitment_i,
            &all_hash_commitments,
        )?;
```

**File:** src/protocol/mod.rs (L62-64)
```rust

    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
```
