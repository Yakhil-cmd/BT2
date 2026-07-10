Looking at the codebase, I need to find an analog to "missing handler causing DoS when unexpected input is received." In threshold-signatures, the analog is a missing error-recovery path in message reception that causes permanent protocol abort.

Let me examine the key discrepancy I found between `recv_from_others` and the echo broadcast's error handling.

The echo broadcast (`echo_broadcast.rs` line 179) explicitly swallows recv errors:
```rust
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,   // ← errors are ignored, loop continues
}
```

But `recv_from_others` (`helpers.rs` line 20) propagates them:
```rust
let (from, msg) = chan.recv(waitpoint).await?;  // ← ? aborts the entire protocol
```

And `push_message` (`internal.rs` lines 286-296) only validates the header, not the payload — so a message with a valid 40-byte header and garbage payload is queued and later causes deserialization failure.

---

### Title
Single Malicious Participant Permanently Aborts DKG/Reshare/Refresh via Malformed Message in `recv_from_others` — (File: `src/protocol/helpers.rs`)

### Summary
`recv_from_others` propagates deserialization errors via `?`, aborting the entire DKG/reshare/refresh protocol when any single participant sends a message with a valid routing header but invalid payload. The echo broadcast rounds explicitly swallow recv errors (`_ => continue`), but the non-broadcast rounds that use `recv_from_others` have no such recovery, creating an inconsistency a malicious participant can exploit to permanently deny key generation to all honest parties.

### Finding Description

**Root cause — `src/protocol/helpers.rs` lines 19-23:**

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;   // propagates DeserializationError
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

`chan.recv` resolves through `Comms::recv` (`src/protocol/internal.rs` lines 330-341), which deserializes the payload with `rmp_serde::decode::from_slice`. On failure it returns `ProtocolError::DeserializationError`, which the `?` in `recv_from_others` immediately propagates, aborting the caller. [1](#0-0) [2](#0-1) 

**Message routing does not validate payloads — `src/protocol/internal.rs` lines 286-296:**

`push_message` only checks that the message is long enough to contain a header and that the header parses. A message with a valid 40-byte header followed by arbitrary garbage passes this check and is queued in the buffer. [3](#0-2) 

**Two vulnerable call sites in `do_keyshare` — `src/dkg.rs`:**

`recv_from_others` is called at two points in the DKG/reshare/refresh core:

- **Line 422-426** — collecting commitment hashes from all participants (Round 2):
  ```rust
  for (from, their_commitment_hash) in
      recv_from_others(&chan, wait_round_1, &participants, me).await?
  ```
- **Line 514-516** — collecting secret shares from all participants (Round 4):
  ```rust
  for (from, signing_share_from) in
      recv_from_others(&chan, wait_round_3, &participants, me).await?
  ```

Both propagate the error with `?`, so a single malformed message in either round aborts `do_keyshare` entirely. [4](#0-3) [5](#0-4) 

**Contrast with echo broadcast — `src/protocol/echo_broadcast.rs` lines 179-182:**

The echo broadcast explicitly ignores recv errors and continues the loop, providing fault tolerance:

```rust
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,
}
``` [6](#0-5) 

This inconsistency means the non-broadcast rounds (commitment hash and secret share exchange) have zero fault tolerance against malformed messages, even though the protocol claims Byzantine resilience up to `floor((N-1)/3)` malicious parties.

### Impact Explanation

A single malicious participant M (even one below the Byzantine fault threshold) can permanently abort DKG, reshare, or refresh for all honest parties:

1. M sends a message to honest party A with a valid header for `wait_round_1` or `wait_round_3` but garbage payload.
2. A's `recv_from_others` dequeues the message, fails deserialization, and aborts with `ProtocolError::DeserializationError`.
3. A never reaches `broadcast_success` and never sends its final-round broadcast.
4. Honest parties B and C are blocked in `reliable_broadcast_receive_all` waiting for A's session to complete — a session that never arrives because A has already exited.
5. B and C wait indefinitely; DKG fails permanently for all honest parties.

This matches **High: Permanent denial of key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions.**

### Likelihood Explanation

Any participant in the protocol can send a malformed message. The attack requires no special privileges, no leaked keys, and no cryptographic breaks. The attacker constructs a 40-byte valid header (32-byte channel tag + 8-byte waitpoint, both deterministic and computable from public information) followed by arbitrary garbage bytes. This is trivially executable by any malicious participant.

### Recommendation

In `recv_from_others`, handle deserialization errors gracefully by ignoring malformed messages and continuing to wait for valid ones, mirroring the echo broadcast's approach:

```rust
while !seen.full() {
    let Ok((from, msg)) = chan.recv(waitpoint).await else {
        continue;   // ignore malformed messages, keep waiting
    };
    if seen.put(from) {
        messages.push((from, msg));
    }
}
``` [7](#0-6) 

### Proof of Concept

1. Participants A, B, C, and malicious M run DKG together.
2. In Round 2 (commitment hash exchange), M sends to A a message whose header encodes the correct channel tag and `wait_round_1` waitpoint, but whose payload is `[0xFF, 0xFF, 0xFF, ...]` (invalid MessagePack).
3. `push_message` accepts the message (header is valid).
4. A's `recv_from_others` dequeues it, `rmp_serde::decode::from_slice` fails, `?` propagates `ProtocolError::DeserializationError`, and A's protocol instance returns an error.
5. A never calls `broadcast_success`; A's final-round `Send` message is never emitted.
6. B and C reach `broadcast_success` → `do_broadcast` → `reliable_broadcast_receive_all`, which loops waiting for all `n` sessions (including A's) to complete. A's session never completes.
7. B and C are permanently blocked. DKG is denied for all honest parties. [3](#0-2) [8](#0-7) [9](#0-8)

### Citations

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

**File:** src/dkg.rs (L531-531)
```rust
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```

**File:** src/protocol/echo_broadcast.rs (L179-182)
```rust
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
```

**File:** src/protocol/echo_broadcast.rs (L322-325)
```rust
                    // we can thus output that the n instances of the broadcast protocols have succeeded
                    if state.iter().all(|x| x.finish_ready) {
                        return Ok(vote_output);
                    }
```
