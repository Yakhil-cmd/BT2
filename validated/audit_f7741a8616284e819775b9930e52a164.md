### Title
Malformed Message Payload from Any Participant Permanently Aborts DKG, Reshare, Refresh, and Signing Protocols - (File: `src/protocol/helpers.rs`, `src/protocol/internal.rs`)

---

### Summary

The `recv_from_others` helper in `src/protocol/helpers.rs` propagates deserialization errors from `SharedChannel::recv` directly via the `?` operator. Because `Comms::recv` in `src/protocol/internal.rs` returns a `ProtocolError::DeserializationError` when any participant's message payload fails MessagePack decoding, a single malicious participant can permanently abort DKG, reshare, refresh, or signing for all honest parties by sending one message with a valid routing header but a malformed payload body.

---

### Finding Description

**Root cause — `Comms::recv` propagates deserialization failure as a fatal error:**

In `src/protocol/internal.rs` lines 330–341, `Comms::recv` pops a buffered message, strips the header, and attempts to decode the remaining bytes with `rmp_serde`:

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
    Ok((from, decoded?))   // <-- propagates deserialization error
}
```

If `decoded` is `Err`, the `?` at line 340 converts it to `ProtocolError::Other(...)` and returns it. There is no retry, no skip-and-continue, and no identification of the offending sender for the caller to act on.

**Admission gate — `push_message` only validates the header, not the payload:**

In `src/protocol/internal.rs` lines 286–296, `push_message` silently drops messages that are too short or have an unparseable header, but it accepts any message whose first `MessageHeader::LEN` (40) bytes form a valid header, regardless of what follows:

```rust
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
```

An attacker who knows the channel tag (derived deterministically from `ChannelTag::root_shared()` and the waitpoint counter) can craft a message that passes this gate but carries garbage after byte 40.

**Propagation — `recv_from_others` uses `?` unconditionally:**

In `src/protocol/helpers.rs` lines 19–24:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;  // <-- fatal on any error
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

The `?` immediately returns the `DeserializationError` to the caller. There is no mechanism to skip the offending participant and wait for the next message.

**Protocol termination — `ProtocolExecutor::poke` stores the error and drops the future:**

In `src/protocol/internal.rs` lines 505–508:

```rust
if let std::task::Poll::Ready(result) = fut.poll_unpin(&mut cx) {
    self.result = Some(result);
    self.fut = None;   // future is dropped; protocol is permanently dead
}
```

Once the async future resolves to `Err`, `self.fut` is set to `None`. Subsequent calls to `poke()` return `Action::Wait` (line 498) forever, or return the stored error on the next call (line 488–490). The protocol cannot be restarted from this state.

**Affected call sites in production code:**

- `src/dkg.rs` line 423: `recv_from_others(&chan, wait_round_1, &participants, me).await?` — collects commitment hashes in DKG Round 1.
- `src/dkg.rs` line 515: `recv_from_others(&chan, wait_round_3, &participants, me).await?` — collects secret shares in DKG Round 5.
- All signing, presigning, and CKD protocols that call `chan.recv(waitpoint).await?` or `recv_from_others` follow the same pattern.

---

### Impact Explanation

A single malicious participant who is a valid member of the protocol session can permanently abort DKG, reshare, refresh, or signing for every honest party by sending one message with a valid 40-byte header and a garbage payload. The honest party's `ProtocolExecutor` future is dropped and cannot be resumed. The entire key generation or signing session must be restarted from scratch, and the attacker can repeat the attack indefinitely, achieving **permanent denial of DKG and signing** for honest parties.

This matches the allowed impact: **High — Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

Any participant in the protocol session can execute this attack. The channel tag is deterministic and computable from public parameters (`ChannelTag::root_shared()` + the waitpoint counter). The attacker only needs to send one message per session. No cryptographic material or privileged access is required beyond being a registered participant. The attack is trivially repeatable across every session restart.

---

### Recommendation

1. **Skip-and-continue on deserialization failure in `recv_from_others`:** Instead of propagating the error, log the offending sender and continue waiting for a valid message from another participant (or re-request). This mirrors the echo-broadcast loop's `continue` pattern already used in `reliable_broadcast_receive_all`.

2. **Return the offending sender alongside the error in `Comms::recv`:** Change the signature to `Result<(Participant, T), (Participant, ProtocolError)>` so callers can attribute and penalize the malicious sender rather than aborting the entire session.

3. **Validate payload structure before buffering in `push_message`:** Perform a lightweight structural check (e.g., verify the MessagePack framing) at ingress so malformed messages are dropped before they reach `recv`.

---

### Proof of Concept

```
Setup: 3-of-3 DKG session with participants P0 (honest), P1 (honest), P2 (malicious).

1. P2 computes the shared channel tag:
       tag = SHA256(NEAR_CHANNEL_TAGS_DOMAIN || "root shared")
   and the waitpoint for DKG Round 1 (waitpoint = 0, the first next_waitpoint() call).

2. P2 constructs a message:
       message = tag_bytes (32) || waitpoint_le (8) || 0xFF 0xFF 0xFF  (invalid msgpack)

3. P2 calls Protocol::message(P2, message) on P0's protocol instance.

4. push_message accepts it (header parses correctly).

5. P0's do_keyshare calls recv_from_others(..., wait_round_1, ...).
   chan.recv(wait_round_1) pops P2's message, rmp_serde fails to decode the payload,
   returns ProtocolError::Other("...").

6. recv_from_others propagates via `?`.

7. do_keyshare's async future resolves to Err.

8. ProtocolExecutor sets self.fut = None.

9. P0 can never complete DKG. The session must be restarted.
   P2 repeats step 2–3 on every restart, permanently blocking key generation.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/protocol/internal.rs (L505-508)
```rust
            if let std::task::Poll::Ready(result) = fut.poll_unpin(&mut cx) {
                self.result = Some(result);
                self.fut = None;
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
