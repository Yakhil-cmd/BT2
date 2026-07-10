### Title
Single Malicious Participant Can Abort DKG/Reshare/Refresh for All Honest Parties via Malformed Message Deserialization — (`src/protocol/helpers.rs`)

---

### Summary

`recv_from_others` propagates deserialization errors from received messages directly to the caller with `?`. A single malicious (but legitimately enrolled) participant can send a message with a syntactically valid routing header but an invalid MessagePack payload. When any honest party's protocol future calls `recv_from_others`, the deserialization failure is returned as a hard `ProtocolError`, immediately aborting the entire `do_keyshare` execution for that party. Because the malformed broadcast reaches every honest party simultaneously, the entire DKG, reshare, or refresh session is destroyed in one shot.

---

### Finding Description

**Root cause — `recv_from_others` does not tolerate deserialization failures:** [1](#0-0) 

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;   // ← hard propagation
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

`chan.recv` internally calls `Comms::recv`, which deserializes the payload with `rmp_serde`: [2](#0-1) 

```rust
async fn recv<T: DeserializeOwned>(…) -> Result<(Participant, T), ProtocolError> {
    let (from, data) = self.incoming.pop(header).await;
    let message_data = data.get(MessageHeader::LEN..).ok_or_else(|| {
        ProtocolError::DeserializationError(…)
    })?;
    let decoded: Result<T, …> =
        rmp_serde::decode::from_slice(message_data).map_err(Into::into);
    Ok((from, decoded?))          // ← error returned to caller
}
```

If `decoded` is `Err`, the error propagates through `recv_from_others` via `?`, terminating the async future and causing `do_keyshare` to return `Err`.

**`recv_from_others` is called at two critical points in `do_keyshare`:**

Round 2 — receiving commitment hashes from all participants: [3](#0-2) 

Round 5 — receiving secret shares from all participants: [4](#0-3) 

**The message routing header is fully predictable.** The channel tag is a SHA-256 hash of a public domain constant and the string `"root shared"`, and the waitpoint is a monotonically incrementing counter starting at 0: [5](#0-4) [6](#0-5) 

`push_message` accepts any message whose first 40 bytes parse as a valid `MessageHeader`, without validating the payload: [7](#0-6) 

A malicious participant therefore constructs: `[40-byte valid header] ++ [garbage bytes]`. This passes `push_message` and lands in the correct per-header queue. When the honest party's `recv_from_others` loop pops it, deserialization fails and the protocol aborts.

**Contrast with the echo broadcast, which handles this correctly:** [8](#0-7) 

```rust
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,   // ← malformed messages are silently skipped
};
```

The echo broadcast rounds are resilient; the `recv_from_others` rounds are not. This is an internal design inconsistency.

---

### Impact Explanation

A single enrolled malicious participant sends a broadcast message (via `send_many`) with a valid header for the Round-2 commitment-hash waitpoint but a garbage payload. Because `send_many` delivers to **all** other participants, every honest party's `recv_from_others` call pops the same malformed message, fails deserialization, and returns `Err`. The entire DKG/reshare/refresh session is aborted for all honest parties simultaneously. The malicious participant can repeat this on every retry, permanently preventing key generation or resharing with that participant set under the documented Byzantine fault model.

This matches: **High — Permanent denial of key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

- The attacker is a legitimately enrolled participant (no external compromise required).
- The channel tag and waitpoint are deterministic and publicly derivable from constants in the source.
- Constructing the malformed message requires only knowledge of the 40-byte header format.
- The attack succeeds on the very first round of `do_keyshare`, before any cryptographic verification occurs.
- No special timing or race condition is needed.

---

### Recommendation

Mirror the echo broadcast's error-handling pattern inside `recv_from_others`: on a deserialization failure, log or record the offending sender and `continue` the loop rather than propagating the error. Optionally, track participants who repeatedly send malformed messages and surface them as `MaliciousParticipant` errors only after the round completes (or after a configurable tolerance is exceeded).

```rust
while !seen.full() {
    let recv_result = chan.recv::<T>(waitpoint).await;
    match recv_result {
        Ok((from, msg)) => {
            if seen.put(from) {
                messages.push((from, msg));
            }
        }
        Err(_) => {
            // Malformed message: skip and wait for the next one.
            continue;
        }
    }
}
```

---

### Proof of Concept

1. Participant set: `{P0, P1, P2}`, threshold 2. `P2` is malicious.
2. `P2` computes the Round-2 commitment-hash waitpoint: `SharedChannel` root tag (SHA-256 of `NEAR_CHANNEL_TAGS_DOMAIN || "root shared"`) with waitpoint `= 2` (after two `do_broadcast` calls consume waitpoints 0 and 1).
3. `P2` calls `Protocol::message` on `P0` and `P1` with payload `[header_bytes] ++ [0xFF, 0xFF, 0xFF]` (invalid MessagePack).
4. `P0` and `P1` each enter `recv_from_others` for the commitment-hash round. They pop `P2`'s malformed message, `rmp_serde::decode::from_slice` returns `Err`, `decoded?` propagates the error, and `do_keyshare` returns `Err` for both honest parties.
5. DKG fails. `P2` can repeat on every retry, permanently blocking key generation with this participant set.

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

**File:** src/protocol/internal.rs (L176-180)
```rust
    fn next_waitpoint(&mut self) -> Waitpoint {
        let out = self.waitpoint;
        self.waitpoint += 1;
        out
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

**File:** src/dkg.rs (L514-528)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        // Step 5.3
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
    }
```

**File:** src/protocol/echo_broadcast.rs (L179-182)
```rust
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
```
