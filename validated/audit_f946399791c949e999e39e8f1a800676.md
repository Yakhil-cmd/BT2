### Title
Malformed Message Injection via `recv_from_others` Causes Permanent Protocol Abort — (`File: src/protocol/helpers.rs`)

### Summary

The `recv_from_others` helper propagates deserialization errors directly to callers via the `?` operator. Any participant in the protocol can inject a syntactically valid but payload-malformed message targeting the correct channel tag and waitpoint, causing `chan.recv()` to return a `ProtocolError::DeserializationError`. This immediately aborts DKG, reshare, refresh, and FROST signing for all honest parties.

### Finding Description

`recv_from_others` is the shared primitive used to collect one message from every other participant before a protocol round can proceed:

```rust
// src/protocol/helpers.rs lines 19-24
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;   // ← error propagated unconditionally
    if seen.put(from) {
        messages.push((from, msg));
    }
}
``` [1](#0-0) 

`chan.recv()` deserializes the raw payload before the `from` field is validated against the participant list:

```rust
// src/protocol/internal.rs lines 330-341
async fn recv<T: DeserializeOwned>(...) -> Result<(Participant, T), ProtocolError> {
    let (from, data) = self.incoming.pop(header).await;
    ...
    let decoded = rmp_serde::decode::from_slice(message_data)...;
    Ok((from, decoded?))   // ← deserialization error surfaces here
}
``` [2](#0-1) 

Because `push_message` accepts any `(Participant, MessageData)` pair without validating that `from` belongs to the participant list, an attacker can inject a message with a valid `MessageHeader` (correct `ChannelTag` + correct `Waitpoint`) but a malformed msgpack payload. The message is queued, popped by `recv_from_others`, deserialization fails, and the `?` aborts the entire protocol future.

This contrasts with the echo broadcast, which explicitly swallows errors to remain robust:

```rust
// src/protocol/echo_broadcast.rs lines 179-182
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,   // ← malformed messages are silently skipped
};
``` [3](#0-2) 

`recv_from_others` has no equivalent guard. The affected call sites are:

| File | Lines | Protocol Phase |
|---|---|---|
| `src/dkg.rs` | 422–426 | DKG/Reshare/Refresh — commitment hash round |
| `src/dkg.rs` | 514–516 | DKG/Reshare/Refresh — signing share round |
| `src/frost/eddsa/sign.rs` | 126–128 | FROST signing — commitment collection (coordinator) |
| `src/frost/eddsa/sign.rs` | 150–153 | FROST signing — signature share collection (coordinator) | [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

The `MessageBuffer` accepts messages for any `MessageHeader` without restriction:

```rust
// src/protocol/internal.rs lines 286-296
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
``` [8](#0-7) 

The `ChannelTag` for the shared channel is a deterministic constant (`SHA256(NEAR_CHANNEL_TAGS_DOMAIN || "root shared")`), and waitpoints are sequential counters starting at 0. Both values are fully predictable by any observer of the protocol structure. [9](#0-8) 

The codebase itself contains a test that explicitly demonstrates unbounded injection into the message buffer:

```rust
// src/protocol/internal.rs lines 532-553
fn attacker_can_fill_message_buffer_with_unused_waitpoints() { ... }
``` [10](#0-9) 

### Impact Explanation

A single malicious participant (one that is legitimately in the participant list) can abort DKG, reshare, refresh, or FROST signing for all honest parties by injecting one malformed message per protocol invocation. Because the attacker can repeat this on every retry, honest parties are permanently denied key generation and signing capability. This matches: **High — Permanent denial of signing, key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions.**

The echo broadcast explicitly tolerates malformed messages and is not affected. The vulnerability is isolated to `recv_from_others` and all callers that rely on it.

### Likelihood Explanation

- The attacker only needs to be a legitimate protocol participant (no special privilege).
- The `ChannelTag` and `Waitpoint` values are fully deterministic and publicly derivable from the protocol structure.
- A single malformed message per round is sufficient to abort the entire protocol.
- The attack is cheap: no cryptographic work is required, only crafting a message with a valid header and invalid msgpack payload.

### Recommendation

Mirror the echo broadcast's error-handling pattern in `recv_from_others`: skip messages that fail deserialization rather than propagating the error:

```rust
while !seen.full() {
    let Ok((from, msg)) = chan.recv(waitpoint).await else {
        continue;  // skip malformed messages
    };
    if seen.put(from) {
        messages.push((from, msg));
    }
}
``` [1](#0-0) 

### Proof of Concept

```
1. Honest parties P1..Pn start DKG. Waitpoint 0 is used for session-id broadcast
   (echo broadcast, robust). Waitpoint 1 is used for commitment hashes via recv_from_others.

2. Attacker (any Pi) constructs:
     header  = ChannelTag::root_shared() || waitpoint=1   (40 bytes, fully deterministic)
     payload = [0xFF, 0xFF, 0xFF]                          (invalid msgpack)
     message = header || payload

3. Attacker calls Protocol::message(Pi, message) on any honest party's protocol instance.

4. Honest party reaches recv_from_others at wait_round_1 (dkg.rs:422).
   chan.recv(1) pops the attacker's message, rmp_serde::decode fails,
   ProtocolError::DeserializationError is returned, ? propagates it,
   do_keyshare returns Err, DKG aborts for that party.

5. Attacker repeats

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

**File:** src/protocol/internal.rs (L532-553)
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
```

**File:** src/protocol/echo_broadcast.rs (L179-182)
```rust
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
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

**File:** src/frost/eddsa/sign.rs (L126-128)
```rust
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }
```

**File:** src/frost/eddsa/sign.rs (L150-153)
```rust
    for (from, signature_share) in recv_from_others(&chan, r2_wait_point, &participants, me).await?
    {
        signature_shares.insert(from.to_identifier()?, signature_share);
    }
```
