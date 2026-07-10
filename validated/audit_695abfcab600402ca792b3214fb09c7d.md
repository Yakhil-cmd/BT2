### Title
Malformed Message Deserialization in `recv_from_others` Causes Permanent DKG/Reshare Denial — (`src/protocol/helpers.rs`)

---

### Summary

A malicious protocol participant can send a message with a syntactically valid routing header but a malformed MessagePack payload. When an honest participant's protocol calls `recv_from_others`, it pops the malformed message, fails to deserialize it, and the `?` operator immediately propagates the error, permanently terminating DKG, reshare, or refresh for that honest party.

---

### Finding Description

**Root cause — `Comms::recv` consumes the message before deserialization can be retried:**

In `src/protocol/internal.rs`, `Comms::recv` (lines 330–341) first pops a message from the buffer (consuming it permanently), then attempts MessagePack deserialization:

```rust
async fn recv<T: DeserializeOwned>(
    &self,
    header: MessageHeader,
) -> Result<(Participant, T), ProtocolError> {
    let (from, data) = self.incoming.pop(header).await;   // consumed here
    let message_data = data.get(MessageHeader::LEN..).ok_or_else(|| {
        ProtocolError::DeserializationError("Failed to deserialize message data".to_string())
    })?;
    let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
        rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
    Ok((from, decoded?))   // error propagated here
}
``` [1](#0-0) 

If `rmp_serde::decode::from_slice` fails, the message is gone and a `ProtocolError::DeserializationError` is returned.

**Propagation — `recv_from_others` does not handle the error:**

`recv_from_others` in `src/protocol/helpers.rs` calls `chan.recv(waitpoint).await?` with a bare `?`:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;   // error terminates the loop
    if seen.put(from) {
        messages.push((from, msg));
    }
}
``` [2](#0-1) 

Any deserialization failure immediately exits the function with an error, which propagates up through `do_keyshare` via `?` at both DKG round-1 (commitment hash collection) and round-3 (signing share collection): [3](#0-2) [4](#0-3) 

**Injection is possible — `push_message` validates only the header:**

`push_message` silently drops messages with an invalid or too-short header, but stores any message whose header parses correctly, regardless of payload content:

```rust
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);   // payload not validated
}
``` [5](#0-4) 

The `MessageHeader` consists of a deterministic SHA-256-derived `ChannelTag` and a sequential `Waitpoint`. Both are fully computable by any participant: [6](#0-5) 

A malicious participant therefore constructs a message whose first `MessageHeader::LEN` bytes form a valid header for the target waitpoint, followed by arbitrary garbage bytes. `push_message` accepts it; `recv` later pops and fails to deserialize it.

**Contrast with the resilient echo-broadcast path:**

`reliable_broadcast_receive_all` in `src/protocol/echo_broadcast.rs` already handles this correctly by matching on the result and continuing on error:

```rust
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,   // malformed message is skipped
};
``` [7](#0-6) 

`recv_from_others` lacks this protection, making every protocol round that uses it vulnerable.

---

### Impact Explanation

A single malicious participant can permanently abort DKG, reshare, or refresh for any honest party by injecting one malformed message at the correct waitpoint. The honest party's protocol terminates with `ProtocolError::DeserializationError` and cannot recover, because the message buffer entry is consumed and the async state machine has no retry path. This matches:

> **High: Permanent denial of key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

The attack requires only that the adversary be a registered participant in the protocol session (the `Protocol::message` entry point accepts messages from any declared participant). The channel tag and waitpoint are deterministic and publicly derivable. The attacker needs to send exactly one crafted message before the victim's `recv_from_others` call completes. This is straightforward for any participant who controls their own network stack.

---

### Recommendation

Mirror the pattern already used in `reliable_broadcast_receive_all`: catch deserialization errors inside `recv_from_others` and skip the offending message rather than propagating the error. For example:

```rust
while !seen.full() {
    let result = chan.recv(waitpoint).await;
    let (from, msg) = match result {
        Ok(v) => v,
        Err(_) => continue,   // skip malformed messages
    };
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

Optionally, log the sender identity for auditability. This is consistent with the existing resilience design in `echo_broadcast.rs`.

---

### Proof of Concept

1. Participants A (honest), B (honest), M (malicious) initiate DKG via `do_keygen`.
2. M computes the shared channel tag (`ChannelTag::root_shared()`, a fixed SHA-256 value) and the waitpoint for `wait_round_1` (the first `next_waitpoint()` call after the two waitpoints consumed by the session-ID broadcast).
3. M constructs a byte string: `[correct_channel_tag (32 bytes) || correct_waitpoint_le (8 bytes) || 0xFF 0xFF 0xFF ...]` (garbage MessagePack payload).
4. M delivers this byte string to A's protocol instance via `Protocol::message(M, crafted_bytes)`.
5. `push_message` parses the header successfully and enqueues the message.
6. A's `do_keyshare` calls `recv_from_others(&chan, wait_round_1, ...)`.
7. `chan.recv(wait_round_1)` pops M's message; `rmp_serde::decode::from_slice` fails on the garbage payload.
8. The `?` in `recv_from_others` propagates `ProtocolError::DeserializationError`.
9. A's DKG terminates permanently. No key material is produced. [8](#0-7) [1](#0-0) [9](#0-8)

### Citations

**File:** src/protocol/internal.rs (L77-121)
```rust
    fn root_shared() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(NEAR_CHANNEL_TAGS_DOMAIN);
        hasher.update(b"root shared");
        let out = hasher.finalize().into();
        Self(out)
    }

    /// The channel tag for a private channel.
    ///
    /// This will always yield the same tag, and is intended to be the root for private channels.
    ///
    /// This tag will depend on the set of participants used; the order they're passed into this
    /// function does not matter.
    fn root_private(p0: Participant, p1: Participant) -> Self {
        // Sort participants, for uniqueness.
        let (p0, p1) = (p0.min(p1), p0.max(p1));

        let mut hasher = Sha256::new();
        hasher.update(NEAR_CHANNEL_TAGS_DOMAIN);
        hasher.update(b"root private");
        hasher.update(b"p0");
        hasher.update(p0.bytes());
        hasher.update(b"p1");
        hasher.update(p1.bytes());

        let out = hasher.finalize().into();
        Self(out)
    }

    /// Get the ith child of this tag.
    ///
    /// Each child has its own "namespace", with its children being distinct.
    ///
    /// Indexed children have a separate namespace from named children.
    fn child(&self, i: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(NEAR_CHANNEL_TAGS_DOMAIN);
        hasher.update(b"parent");
        hasher.update(self.0);
        hasher.update(b"i");
        hasher.update(i.to_le_bytes());
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

**File:** src/protocol/internal.rs (L330-341)
```rust
    async fn recv<T: DeserializeOwned>(
        &self,
        header: MessageHeader,
    ) -> Result<(Participant, T), ProtocolError> {
        let (from, data) = self.incoming.pop(header).await;
        let message_data = data.get(MessageHeader::LEN..).ok_or_else(|| {
            ProtocolError::DeserializationError("Failed to deserialize message data".to_string())
        })?;
        let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
            rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
        Ok((from, decoded?))
    }
```

**File:** src/protocol/helpers.rs (L6-27)
```rust
pub async fn recv_from_others<T>(
    chan: &SharedChannel,
    waitpoint: u64,
    participants: &ParticipantList,
    me: Participant,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let mut messages = Vec::with_capacity(participants.others(me).count());

    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
}
```

**File:** src/dkg.rs (L413-426)
```rust
    // Step 2.9
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &commitment_hash)?;
    // receive commitment_hash

    let mut all_hash_commitments = ParticipantMap::new(&participants);
    all_hash_commitments.put(me, commitment_hash);

    // Step 3.1
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
