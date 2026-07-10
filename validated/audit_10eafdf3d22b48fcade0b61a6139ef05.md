The exploit path is concrete. Let me trace it precisely through the code.

**Deserialization path:**

1. `do_ckd_coordinator` calls `recv_from_others::<CKDOutput>` at line 51 of `protocol.rs` [1](#0-0) 

2. `recv_from_others` calls `chan.recv(waitpoint).await?` — the `?` propagates any error immediately [2](#0-1) 

3. `SharedChannel::recv` delegates to `Comms::recv`, which calls `rmp_serde::decode::from_slice` and propagates failure via `decoded?` [3](#0-2) 

**The critical issue:** `CKDOutput` contains two `ElementG1` (`blstrs::G1Projective`) fields. If a participant sends a msgpack payload where those 48-byte compressed-point fields fail `blstrs` deserialization (e.g., compression flag set but point not on the curve), `rmp_serde::decode::from_slice` returns an error. That error propagates via `decoded?` → `SharedChannel::recv` → `recv_from_others` (via `?`) → `do_ckd_coordinator` (via `?`), terminating the coordinator with a `ProtocolError`. [4](#0-3) 

There is **no error recovery** in `recv_from_others` — it does not skip malformed messages, retry, or continue to the next sender. A single malformed message from any participant immediately aborts the loop. [2](#0-1) 

---

### Title
Malicious participant can permanently abort CKD coordinator via invalid G1 point deserialization - (`src/confidential_key_derivation/protocol.rs`)

### Summary
A single malicious participant in a CKD session can permanently abort the coordinator by sending a msgpack-encoded `CKDOutput` payload whose `big_y` or `big_c` bytes encode an invalid compressed BLS12-381 G1 point. The deserialization error propagates unhandled through `recv_from_others`, terminating the coordinator with a `ProtocolError`.

### Finding Description
`do_ckd_coordinator` collects contributions from all participants via `recv_from_others::<CKDOutput>`. Internally, `Comms::recv` deserializes each incoming message using `rmp_serde::decode::from_slice`. `CKDOutput` contains two `blstrs::G1Projective` fields (`big_y`, `big_c`). If the 48-byte compressed-point representation fails `blstrs` point validation (e.g., compression flag set but bytes do not correspond to a curve point), deserialization returns an error. This error propagates via `decoded?` in `Comms::recv`, then via `?` in `recv_from_others`, then via `?` in `do_ckd_coordinator`, immediately terminating the coordinator. There is no mechanism to skip, ignore, or attribute the failure to the offending participant.

### Impact Explanation
Any participant registered in the CKD session can unilaterally and permanently abort the coordinator for that session. Since the CKD protocol is single-round with no restart mechanism, the session cannot recover. All honest parties are denied the CKD output. This matches: **High — Permanent denial of CKD for honest parties under valid protocol inputs and documented trust assumptions**.

### Likelihood Explanation
The attacker only needs to be a registered participant (a normal precondition). The attack requires crafting a single malformed message and delivering it via the public `Protocol::message()` API. No cryptographic assumptions need to be broken. The attack is deterministic and requires no timing or race conditions.

### Recommendation
In `recv_from_others` (or in `Comms::recv`), deserialization errors should be attributed to the sending participant and treated as a skippable/attributable fault rather than a fatal protocol error. Options include:
- Returning `Result<Vec<(Participant, T)>, ProtocolError>` where individual decode failures are logged and the offending participant is excluded (if the protocol can tolerate fewer contributors).
- Wrapping the `decoded?` in `Comms::recv` to return a per-message `Result` so callers can decide whether to abort or skip.
- Applying the same pattern used in `echo_broadcast.rs` where `chan.recv` errors are caught and the loop continues (`_ => continue`). [5](#0-4) 

### Proof of Concept
```rust
// Craft a CKDOutput msgpack payload with invalid G1 point bytes:
// big_y = [0x80, 0x00, ..., 0x01] (48 bytes, compression flag set, not on curve)
// big_c = same
// Encode as msgpack struct with two bin-48 fields.
// Deliver via Protocol::message(coordinator_participant, crafted_bytes).
// Assert coordinator's next poke() returns Err(ProtocolError::DeserializationError(...)).
```

The path through `Comms::recv` at `src/protocol/internal.rs:339-340` is the root cause: `rmp_serde::decode::from_slice` failure on invalid `blstrs::G1Projective` bytes propagates directly as a fatal `ProtocolError` with no per-sender isolation. [6](#0-5)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
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

**File:** src/confidential_key_derivation/mod.rs (L31-35)
```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CKDOutput {
    big_y: ElementG1,
    big_c: ElementG1,
}
```

**File:** src/protocol/echo_broadcast.rs (L179-182)
```rust
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
```
