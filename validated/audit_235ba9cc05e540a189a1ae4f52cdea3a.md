Now I have all the information needed. Let me trace the exact execution path.

### Title
Malicious Participant Aborts Honest Participant's Signing Session via Deserialization Error Before `from` Check — (`src/frost/redjubjub/sign.rs`)

---

### Summary

In `do_sign_participant`, the `wait_round_1` receive loop applies the `?` operator to `chan.recv()` before it can check whether the sender is the coordinator. Because `Comms::recv` returns `Err` on any deserialization failure, a malicious non-coordinator participant can inject a message with a valid channel header but an undeserializable payload, causing the honest participant's signing session to abort permanently.

---

### Finding Description

`do_sign_participant` waits for the coordinator's `Randomizer` in a loop:

```rust
let randomizer = loop {
    let (from, randomizer): (_, Randomizer) = chan.recv(wait_round_1).await?;
    if from != coordinator {
        continue;
    }
    break randomizer;
};
``` [1](#0-0) 

The intent is to skip messages from non-coordinators via `continue`. However, `chan.recv` delegates to `Comms::recv`, which deserializes the payload **before** returning the `(from, value)` tuple:

```rust
async fn recv<T: DeserializeOwned>(...) -> Result<(Participant, T), ProtocolError> {
    let (from, data) = self.incoming.pop(header).await;
    ...
    let decoded: Result<T, ...> = rmp_serde::decode::from_slice(message_data)...;
    Ok((from, decoded?))   // <-- Err propagated here if deserialization fails
}
``` [2](#0-1) 

If deserialization fails, `Comms::recv` returns `Err(ProtocolError::DeserializationError(...))`. The `?` in `chan.recv(wait_round_1).await?` propagates this error immediately — the `if from != coordinator { continue; }` guard is **never reached**.

The message ingestion path (`push_message`) accepts messages from any participant as long as the channel header parses correctly; there is no sender-based pre-filter:

```rust
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
``` [3](#0-2) 

A malicious participant who knows the deterministic channel header for `wait_round_1` (it is computed from a root shared tag plus a monotonic waitpoint counter, both of which are protocol-public) can craft a message with a valid header prefix and a garbage payload. This message is queued, dequeued by `chan.recv`, fails deserialization, and the `Err` aborts the victim's signing future.

---

### Impact Explanation

The signing session for the honest participant is permanently terminated. The nonces and presignature material for that round are consumed and cannot be reused (nonces are zeroized on drop). The coordinator will time out waiting for the participant's signature share, and the threshold signing round fails. This matches the **High** impact category: *Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions*.

---

### Likelihood Explanation

Any participant in the signing group can execute this attack. The channel header for `wait_round_1` is fully deterministic (root shared tag + waitpoint index 0), so it can be computed without any secret knowledge. The attacker only needs to deliver one malformed message before the coordinator's legitimate `Randomizer` arrives. In a network where message ordering is not strictly enforced, this is straightforward.

---

### Recommendation

Move deserialization errors out of the fatal path inside the coordinator-filter loop. The fix is to handle `Err` from `chan.recv` as a `continue` (skip) rather than a fatal abort when the loop is specifically designed to tolerate non-coordinator messages:

```rust
let randomizer = loop {
    let result: Result<(_, Randomizer), _> = chan.recv(wait_round_1).await;
    match result {
        Ok((from, randomizer)) if from == coordinator => break randomizer,
        Ok(_) | Err(_) => continue,  // skip non-coordinator or malformed messages
    }
};
```

The same pattern applies to the analogous loop in `src/frost/eddsa/sign.rs` (`do_sign_participant_v1`, lines 273–280). [4](#0-3) 

---

### Proof of Concept

1. Participant A is the honest non-coordinator in a signing session.
2. Malicious participant B computes the `wait_round_1` channel header (root shared tag + waitpoint 0).
3. B sends a message to A with the correct header prefix followed by random bytes that cannot be deserialized as `Randomizer` (e.g., `[0xFF, 0xFF, 0xFF, ...]`).
4. A's `do_sign_participant` loop calls `chan.recv(wait_round_1)`, dequeues B's message, `rmp_serde::decode::from_slice` fails, `Comms::recv` returns `Err`, the `?` propagates it, and A's signing future returns `Err(ProtocolError::DeserializationError(...))`.
5. The coordinator never receives A's signature share; the signing round fails.
6. Fuzz test: inject random bytes at `wait_round_1` from a non-coordinator participant and assert the participant loop does **not** abort before receiving the coordinator's message — this assertion will currently fail.

### Citations

**File:** src/frost/redjubjub/sign.rs (L217-223)
```rust
    let randomizer = loop {
        let (from, randomizer): (_, Randomizer) = chan.recv(wait_round_1).await?;
        if from != coordinator {
            continue;
        }
        break randomizer;
    };
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

**File:** src/frost/eddsa/sign.rs (L273-280)
```rust
    let signing_package = loop {
        let (from, signing_package): (_, frost_ed25519::SigningPackage) =
            chan.recv(r2_wait_point).await?;
        if from != coordinator {
            continue;
        }
        break signing_package;
    };
```
