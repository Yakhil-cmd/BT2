### Title
Malicious Participant Sends Malformed Message to Permanently Abort DKG, Reshare, Refresh, and Signing via Unhandled Deserialization Error in `recv_from_others` - (File: src/protocol/helpers.rs)

---

### Summary

`recv_from_others` in `src/protocol/helpers.rs` propagates deserialization errors from `chan.recv()` directly to callers via `?`. A malicious participant can craft a message with a syntactically valid `MessageHeader` but an invalid msgpack body, causing `Comms::recv` to return `Err(ProtocolError::DeserializationError(...))`. This error propagates through `recv_from_others` and permanently aborts DKG, reshare, refresh, and any signing protocol that relies on this helper for honest parties.

---

### Finding Description

`recv_from_others` is the primary helper used by all multi-round protocols to collect one message per participant before advancing:

```rust
// src/protocol/helpers.rs:19-24
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;   // <-- error propagates here
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

`chan.recv()` internally calls `Comms::recv`, which deserializes the raw bytes after stripping the header:

```rust
// src/protocol/internal.rs:338-340
let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
    rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
Ok((from, decoded?))   // <-- deserialization error returned as Err
``` [1](#0-0) [2](#0-1) 

The `Comms::push_message` entry point accepts any message whose first `MessageHeader::LEN` (40) bytes parse as a valid header, with no validation of the body:

```rust
// src/protocol/internal.rs:286-296
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
``` [3](#0-2) 

A malicious participant constructs a message whose first 40 bytes encode the correct `ChannelTag` (root shared) and the current `waitpoint`, followed by arbitrary garbage bytes. When an honest party's `recv_from_others` loop pops this message, `rmp_serde::decode::from_slice` fails, the `?` operator propagates the error, and the protocol permanently aborts.

This is in direct contrast to `reliable_broadcast_receive_all`, which correctly swallows deserialization errors:

```rust
// src/protocol/echo_broadcast.rs:179-182
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,   // silently ignored
}
``` [4](#0-3) 

`recv_from_others` is called at every non-broadcast round of DKG:

```rust
// src/dkg.rs:422-426  (Round 2: commitment hash collection)
for (from, their_commitment_hash) in
    recv_from_others(&chan, wait_round_1, &participants, me).await?
// src/dkg.rs:514-516  (Round 5: secret share collection)
for (from, signing_share_from) in
    recv_from_others(&chan, wait_round_3, &participants, me).await?
``` [5](#0-4) [6](#0-5) 

The same helper is used in FROST signing and other protocols, extending the impact surface. [7](#0-6) 

---

### Impact Explanation

A single malicious participant can permanently abort DKG, reshare, refresh, or any signing round that uses `recv_from_others`. Honest parties receive a `ProtocolError::DeserializationError` and cannot distinguish this from a legitimate protocol failure. There is no retry or recovery path; the entire session must be restarted. This maps directly to the allowed impact: **High: Permanent denial of signing, key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions.** [8](#0-7) 

---

### Likelihood Explanation

Any participant registered in the protocol can call `Protocol::message(from, data)` with arbitrary bytes. The attacker only needs to know the correct `ChannelTag` (which is deterministic and derived from a public constant `NEAR_CHANNEL_TAGS_DOMAIN`) and the current waitpoint (which increments sequentially from 0). Both are trivially computable by any participant running the same protocol code. No privileged access, leaked keys, or external compromise is required. [9](#0-8) [10](#0-9) 

---

### Recommendation

Mirror the defensive pattern already used in `reliable_broadcast_receive_all`: silently skip messages that fail to deserialize rather than propagating the error. In `recv_from_others`, replace the propagating `?` with a `match` that continues on error:

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

This is consistent with the existing defensive pattern in `reliable_broadcast_receive_all` and prevents a single malicious participant from aborting the protocol via a crafted message. [7](#0-6) [11](#0-10) 

---

### Proof of Concept

1. Honest parties P1, P2, P3 and malicious party P_m initiate DKG together.
2. All parties reach Round 2 (commitment hash exchange, `wait_round_1`).
3. P_m computes the correct `MessageHeader` for `wait_round_1`:
   - `channel = ChannelTag::root_shared()` (deterministic, derived from `NEAR_CHANNEL_TAGS_DOMAIN` + `"root shared"`)
   - `waitpoint = 1` (the first waitpoint allocated by `chan.next_waitpoint()` after the broadcast round)
4. P_m constructs a 40-byte header encoding these values, followed by `0xFF 0xFF 0xFF` (invalid msgpack).
5. P_m delivers this message to P1 via `P1.message(P_m, crafted_bytes)`.
6. P1's `recv_from_others` loop pops P_m's message, calls `rmp_serde::decode::from_slice` on the garbage body, receives `Err`, and the `?` propagates it as `ProtocolError::DeserializationError(...)`.
7. P1's DKG future returns `Err`, permanently aborting P1's participation. The same attack can be replayed against P2 and P3.
8. DKG never completes; no key shares are produced. [12](#0-11) [1](#0-0) [5](#0-4)

### Citations

**File:** src/protocol/helpers.rs (L6-26)
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

**File:** src/protocol/internal.rs (L367-368)
```rust
    pub fn next_waitpoint(&mut self) -> Waitpoint {
        self.header.next_waitpoint()
```

**File:** src/protocol/echo_broadcast.rs (L175-183)
```rust
        if !is_simulated_vote {
            // The recv should be failure-free
            // This translates to ignoring the received message when deemed wrong
            // types of the received answers are (Participant, (usize, MessageType))
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
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

**File:** src/errors.rs (L92-94)
```rust
    #[error("deserialization failed: {0}")]
    DeserializationError(String),

```
