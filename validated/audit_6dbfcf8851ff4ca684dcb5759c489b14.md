### Title
Malformed Message Injection Causes Unrecoverable DKG/Reshare/Refresh Abort via Unhandled Deserialization Error in `recv_from_others` — (File: `src/protocol/helpers.rs`)

---

### Summary

The `recv_from_others` helper function propagates deserialization errors directly to callers via the `?` operator. A malicious registered participant can inject a message with a syntactically valid routing header but an invalid msgpack payload into the shared message queue. When `recv_from_others` pops and attempts to deserialize this message, the resulting `ProtocolError::DeserializationError` is propagated upward, permanently aborting the DKG, reshare, or refresh protocol for every honest party that calls this function.

---

### Finding Description

`recv_from_others` in `src/protocol/helpers.rs` collects one message per participant before proceeding:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;   // ← error propagated
    if seen.put(from) {
        messages.push((from, msg));
    }
}
``` [1](#0-0) 

`chan.recv` in `src/protocol/internal.rs` deserializes the payload with `rmp_serde` and returns `Err` on failure:

```rust
let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
    rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
Ok((from, decoded?))
``` [2](#0-1) 

The upstream `push_message` function only validates the routing header (channel tag + waitpoint); it does **not** validate the payload:

```rust
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
``` [3](#0-2) 

The shared channel tag is **deterministic and public** (derived from a fixed domain separator), and the waitpoint is **sequential and predictable**:

```rust
fn root_shared() -> Self {
    let mut hasher = Sha256::new();
    hasher.update(NEAR_CHANNEL_TAGS_DOMAIN);
    hasher.update(b"root shared");
    ...
}
``` [4](#0-3) 

A malicious participant therefore constructs a message whose first 40 bytes are the correct `(channel_tag || waitpoint)` and whose remaining bytes are arbitrary garbage. This message passes `push_message`'s header check, is enqueued for the target waitpoint, and when popped by `recv_from_others`, causes a `DeserializationError` that propagates via `?` and terminates the entire DKG execution.

`recv_from_others` is called in two critical DKG rounds in `src/dkg.rs`:

- **Round 1** — collecting commitment hashes from all participants:

```rust
for (from, their_commitment_hash) in
    recv_from_others(&chan, wait_round_1, &participants, me).await?
``` [5](#0-4) 

- **Round 4** — collecting secret signing shares from all participants:

```rust
for (from, signing_share_from) in
    recv_from_others(&chan, wait_round_3, &participants, me).await?
``` [6](#0-5) 

By contrast, the echo broadcast protocol — which is explicitly designed for adversarial settings — silently ignores deserialization failures and continues:

```rust
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,
}
``` [7](#0-6) 

The inconsistency between these two error-handling strategies is the root cause.

---

### Impact Explanation

A single malicious registered participant can permanently abort `do_keyshare` (and therefore `do_keygen`, `do_reshare`, and `do_refresh`) for every honest party. Because DKG is a prerequisite for all threshold signing operations, this constitutes **permanent denial of key generation, reshare, and refresh** for honest parties. The attack can be repeated on every protocol restart, making recovery impossible while the malicious participant remains in the participant set.

**Impact: High** — matches "Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions."

---

### Likelihood Explanation

- The attacker is any registered participant (a realistic adversary model for threshold protocols).
- The shared channel tag is a fixed, publicly computable SHA-256 hash; the waitpoint is a sequential counter starting at 0 — both are trivially known to any participant.
- Crafting the attack message requires only prepending the 40-byte header to arbitrary bytes; no cryptographic material is needed.
- The attack fires on the very first malformed message received, before any duplicate-sender guard (`seen.put`) is checked, because the error occurs inside `chan.recv` before `seen.put` is reached.

**Likelihood: High.**

---

### Recommendation

Mirror the error-handling pattern already used in `reliable_broadcast_receive_all`: skip malformed messages and continue waiting rather than propagating the error. Replace the propagating `?` with explicit error handling:

```rust
while !seen.full() {
    let result = chan.recv::<T>(waitpoint).await;
    let (from, msg) = match result {
        Ok(v) => v,
        Err(_) => continue,   // ignore malformed payload, keep waiting
    };
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

This is the direct analog of replacing `safeApprove` (which aborts on a non-zero state) with `forceApprove` (which proceeds regardless of prior state): instead of aborting on a bad payload, the function discards the bad message and continues collecting valid ones.

---

### Proof of Concept

**Setup:** 4-party DKG with threshold 2. Participants: `P0, P1, P2, P3`. `P3` is malicious.

**Attack steps:**

1. All parties call `do_keygen`. The protocol enters Round 1 (`wait_round_1`).
2. `P3` computes the shared channel tag (deterministic SHA-256 of `NEAR_CHANNEL_TAGS_DOMAIN || "root shared"`) and the waitpoint for Round 1 (value `2`, after the two broadcast waitpoints consumed by `do_broadcast` for session IDs).
3. `P3` constructs a 41-byte message: `channel_tag (32 bytes) || waitpoint_le (8 bytes) || 0xFF` (invalid msgpack).
4. `P3` delivers this message to `P0` via the network layer (calling `P0.message(P3, crafted_bytes)`).
5. `P0`'s `recv_from_others` call pops this message, `rmp_serde::decode::from_slice` fails on `0xFF`, `chan.recv` returns `Err(DeserializationError(...))`, the `?` propagates it, and `do_keyshare` returns an error.
6. `P0` permanently fails DKG. `P3` repeats for `P1` and `P2`.

No valid key material is ever produced. The attack cost is three crafted 41-byte messages.

### Citations

**File:** src/protocol/helpers.rs (L19-24)
```rust
    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }
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

**File:** src/protocol/internal.rs (L338-341)
```rust
        let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
            rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
        Ok((from, decoded?))
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

**File:** src/dkg.rs (L514-516)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
```

**File:** src/protocol/echo_broadcast.rs (L179-182)
```rust
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
```
