### Title
Malicious Participant Aborts DKG/Signing via Crafted Deserialization-Failing Message — (`src/protocol/helpers.rs`)

### Summary

A malicious participant in any DKG, signing, presigning, reshare, refresh, or CKD session can permanently abort the protocol for all honest parties by injecting a message that carries a structurally valid routing header but an invalid msgpack payload. The `recv_from_others` helper propagates the resulting deserialization error directly to the caller via `?`, terminating the protocol future. Because the attack is cheap and repeatable, honest parties can never complete the affected operation.

### Finding Description

**Root cause — `recv_from_others` propagates deserialization errors**

`src/protocol/helpers.rs` lines 19-23:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;   // ← error propagates here
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

`chan.recv` is `Comms::recv` in `src/protocol/internal.rs` lines 330-341:

```rust
async fn recv<T: DeserializeOwned>(
    &self,
    header: MessageHeader,
) -> Result<(Participant, T), ProtocolError> {
    let (from, data) = self.incoming.pop(header).await;
    // ...
    let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
        rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
    Ok((from, decoded?))   // ← returns Err on bad payload
}
```

When `rmp_serde` cannot decode the payload into the expected type `T`, `decoded?` returns `Err(ProtocolError::Other(...))`. The `?` in `recv_from_others` immediately propagates this error to every caller, which also uses `?`, collapsing the entire protocol future.

**Why a malicious participant can trigger this**

The routing header is 40 bytes: a 32-byte SHA-256 channel tag followed by an 8-byte little-endian waitpoint. Both values are fully deterministic and computable by any participant:

- The shared-channel tag is `SHA-256(NEAR_CHANNEL_TAGS_DOMAIN || "root shared")` — a fixed constant. (`src/protocol/internal.rs` lines 77-83)
- The waitpoint is a sequential counter that increments once per `next_waitpoint()` call; any participant observing the protocol flow knows the exact value for each round.

`push_message` (`src/protocol/internal.rs` lines 286-296) accepts any message whose first 40 bytes parse as a valid header and stores it in the buffer keyed by that header. There is no payload pre-validation and no sender allowlist at the buffer level.

A malicious participant therefore:
1. Computes the correct `(channel_tag, waitpoint)` for the target round.
2. Constructs a 40-byte header followed by arbitrary bytes that are not valid msgpack for the expected type `T`.
3. Delivers this message to an honest party's `Protocol::message()` entry point.

The message is buffered. The next `recv_from_others` call pops it, deserialization fails, and the protocol aborts — before the `seen.put(from)` deduplication guard is ever reached.

**Contrast with the echo broadcast protocol**

`reliable_broadcast_receive_all` in `src/protocol/echo_broadcast.rs` lines 179-182 handles the identical situation correctly:

```rust
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,   // ← silently skips bad messages
}
```

`recv_from_others` has no equivalent guard, making it the only unprotected receive path in the library.

**Affected call sites**

- `src/dkg.rs` — Round 2 (commitment hashes) and Round 5 (secret shares) of `do_keyshare`, used by `keygen`, `reshare`, and `refresh`.
- `src/ecdsa/robust_ecdsa/sign.rs` — coordinator's signature-share collection in `do_sign_coordinator`.
- Any other protocol that calls `recv_from_others`.

### Impact Explanation

A single malicious participant can abort DKG, reshare, refresh, or signing for every honest party in the session. Because the attack is free (no cryptographic work required, no stake at risk) and repeatable, honest parties can never successfully complete the targeted operation as long as the malicious participant remains in the session. This constitutes **permanent denial of key generation, reshare, refresh, and signing** for honest parties.

This matches the allowed High impact: *"Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions."*

### Likelihood Explanation

The attacker needs only to be a legitimate participant in the session (no privileged access, no leaked keys). Computing the correct header requires only public information. Crafting an invalid msgpack payload is trivial. The attack can be launched at any round that uses `recv_from_others` and can be repeated every time the honest parties restart the session.

### Recommendation

Mirror the error-handling pattern already used in `reliable_broadcast_receive_all`: skip messages that fail deserialization rather than propagating the error.

```rust
while !seen.full() {
    let result: Result<(Participant, T), _> = chan.recv(waitpoint).await;
    let Ok((from, msg)) = result else { continue };
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

To prevent an infinite loop caused by a participant flooding invalid messages, additionally track per-sender failure counts and abort only when a single sender exceeds a reasonable threshold (e.g., more failures than the total number of participants).

### Proof of Concept

**Setup**: 4-party DKG, participants P0–P3; P3 is malicious.

**Steps**:

1. All four parties start `keygen`. Each calls `do_keyshare`, which calls `do_broadcast` (Round 1) and then `recv_from_others` at Round 2 waitpoint `w2`.

2. P3 computes the shared-channel tag (fixed SHA-256 constant) and the waitpoint `w2` (= 1, after Round 1 consumed waitpoint 0 via `do_broadcast`).

3. P3 constructs a 40-byte header `[channel_tag || w2.to_le_bytes()]` followed by `[0xFF, 0xFF]` (not valid msgpack for the expected commitment-hash type) and delivers this raw byte string to P0's `Protocol::message(P3, ...)` entry point.

4. P0's `recv_from_others` loop pops P3's message, `rmp_serde::decode::from_slice` fails, `Comms::recv` returns `Err(ProtocolError::Other(...))`, the `?` in `recv_from_others` propagates it, and P0's DKG future terminates with an error.

5. P3 repeats step 3 for P1 and P2, aborting the DKG for all honest parties.

6. P3 can repeat this attack on every restart attempt at zero cost.

**Expected outcome**: `keygen` returns `Err(ProtocolError::Other("..."))` for every honest party; no key material is produced. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/protocol/echo_broadcast.rs (L179-182)
```rust
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
```

**File:** src/dkg.rs (L513-516)
```rust
    // Step 5.1
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L138-143)
```rust
    for (_, s_i) in
        recv_from_others::<SerializableScalar<C>>(&chan, wait_round, &participants, me).await?
    {
        // Sum the linearized shares
        s += s_i.0;
    }
```
