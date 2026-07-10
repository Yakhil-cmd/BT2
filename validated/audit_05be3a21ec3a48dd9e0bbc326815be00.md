### Title
Malformed Message Causes Unrecoverable Protocol Termination via Deserialization Error Propagation in `recv_from_others` — (File: `src/protocol/helpers.rs`)

---

### Summary

`recv_from_others` propagates deserialization errors directly to the caller via `?`. When a malicious participant injects a message with a syntactically valid routing header but an invalid payload, `Comms::recv` permanently consumes the message from the internal queue and then returns a `DeserializationError`. The `?` in `recv_from_others` immediately terminates the protocol future. Because the message was already popped from the unbounded channel, it cannot be recovered on restart. A persistent attacker can repeat this on every protocol restart, causing permanent denial of DKG, reshare, refresh, signing, or CKD for all honest parties.

---

### Finding Description

`recv_from_others` in `src/protocol/helpers.rs` collects one message from each other participant at a given waitpoint:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;   // <-- ? propagates error
    if seen.put(from) {
        messages.push((from, msg));
    }
}
``` [1](#0-0) 

`chan.recv` resolves to `Comms::recv`, which first **pops** the message from the `SubMessageQueue` (an `UnboundedReceiver`) and then attempts deserialization:

```rust
async fn recv<T: DeserializeOwned>(&self, header: MessageHeader) -> Result<...> {
    let (from, data) = self.incoming.pop(header).await;   // message consumed here
    ...
    let decoded = rmp_serde::decode::from_slice(message_data)...;
    Ok((from, decoded?))   // error returned AFTER consumption
}
``` [2](#0-1) 

The `pop` call drains the message from the `futures::channel::mpsc::unbounded` channel: [3](#0-2) 

`push_message` accepts any message whose first `MessageHeader::LEN` bytes parse as a valid header, without validating the payload: [4](#0-3) 

A malicious participant therefore only needs to craft a message whose first 40 bytes match the target channel tag and waitpoint (both deterministic and computable), with an arbitrary invalid payload. The message passes `push_message`, is queued, is popped by `Comms::recv`, fails `rmp_serde` deserialization, and the resulting `ProtocolError::DeserializationError` (or `Other`) propagates through `recv_from_others`'s `?` operator, aborting the entire protocol future.

By contrast, `reliable_broadcast_receive_all` explicitly catches and ignores receive errors:

```rust
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,   // errors silently skipped
}
``` [5](#0-4) 

This inconsistency means the echo-broadcast layer is resilient but every protocol round that uses `recv_from_others` is not.

The same pattern exists in `PrivateChannel::recv`, which also propagates deserialization errors via `?`: [6](#0-5) 

---

### Impact Explanation

`recv_from_others` is called in every non-broadcast round of DKG (`do_keyshare`), reshare, refresh, presign, sign, and CKD. A single malformed message at any of these waitpoints terminates the protocol for the receiving honest party. Because the message is consumed before the error is returned, restarting the protocol does not replay the malformed message — but the attacker can inject a new one on every restart. This constitutes **permanent denial of key generation, reshare, refresh, signing, and CKD** for honest parties as long as the malicious participant remains in the protocol set.

Impact: **High** — matches "Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions."

---

### Likelihood Explanation

Any participant listed in the `ParticipantList` can call `message(from, data)` on the `ProtocolExecutor`. The channel tag is a deterministic SHA-256 hash of public constants, and the waitpoint is a sequential counter starting at 0 — both are fully predictable by any participant. Crafting a valid-header/invalid-payload message requires no cryptographic capability. The attack is trivially repeatable across restarts.

---

### Recommendation

Mirror the error-handling pattern already used in `reliable_broadcast_receive_all`: catch deserialization errors inside the receive loop and `continue` rather than propagating them. Alternatively, validate the `from` field against the known participant list before deserialization and discard messages from unknown senders without returning an error. A per-sender deduplication guard (already present in `recv_from_others` via `seen.put`) should be applied before the deserialization step so that a malicious duplicate or malformed message is silently dropped rather than aborting the protocol.

---

### Proof of Concept

1. Honest parties `P1`, `P2`, `P3` start DKG (`do_keygen`). The protocol reaches Round 2 where `recv_from_others` is called at waitpoint `w`.
2. Malicious `P4` (a listed participant) computes the channel tag for the shared channel (deterministic SHA-256 of `NEAR_CHANNEL_TAGS_DOMAIN || "root shared"`) and constructs a 40-byte header with `waitpoint = w`, followed by 4 bytes of garbage payload.
3. `P4` delivers this message to `P1` via `P1.message(P4, crafted_bytes)`.
4. `P1`'s `recv_from_others` pops the message, `rmp_serde::decode::from_slice` fails, `decoded?` returns `ProtocolError::Other(...)`, the `?` in `recv_from_others` propagates it, and `do_keyshare` returns `Err(...)`.
5. `P1` restarts DKG. `P4` repeats step 2–4. `P1` can never complete key generation. [7](#0-6) [8](#0-7)

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

**File:** src/protocol/internal.rs (L190-201)
```rust
struct SubMessageQueue {
    sender: futures::channel::mpsc::UnboundedSender<(Participant, MessageData)>,
    receiver: Arc<Mutex<futures::channel::mpsc::UnboundedReceiver<(Participant, MessageData)>>>,
}

impl SubMessageQueue {
    pub fn send(&self, from: Participant, message: MessageData) {
        // This cannot fail because the receiver is also alive.
        self.sender
            .unbounded_send((from, message))
            .expect("unbound_send should not fail");
    }
```

**File:** src/protocol/internal.rs (L245-255)
```rust
    async fn pop(&self, header: MessageHeader) -> (Participant, MessageData) {
        let receiver = {
            let mut messages_lock = self.messages.lock().expect("lock should not fail");
            messages_lock.entry(header).or_default().receiver.clone()
        };
        let mut receiver_lock = receiver.lock().await;
        receiver_lock
            .next()
            .await
            .expect("Reference to sender held")
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

**File:** src/protocol/internal.rs (L440-444)
```rust
        loop {
            let (from, data) = self
                .comms
                .recv(self.header.with_waitpoint(waitpoint))
                .await?;
```

**File:** src/protocol/echo_broadcast.rs (L179-182)
```rust
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
```
