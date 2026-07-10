### Title
Malformed Message Injection via `recv_from_others` Causes Permanent Abort of DKG/Reshare/Refresh — (File: `src/protocol/helpers.rs`)

---

### Summary

A malicious participant can permanently abort DKG, reshare, or refresh protocols for all honest parties by sending a message with a syntactically valid routing header but an invalid (e.g., random-byte) payload at a critical waitpoint. The `recv_from_others` helper propagates deserialization errors via `?` with no recovery path, while the echo-broadcast layer in the same codebase explicitly skips malformed messages and continues. The inconsistency means a single malicious participant can repeatedly abort every DKG attempt, permanently denying key generation to honest parties.

---

### Finding Description

`recv_from_others` in `src/protocol/helpers.rs` is the sole mechanism used by `do_keyshare` in `src/dkg.rs` to collect point-to-point messages in two critical rounds:

- **Round 1** (`wait_round_1`, line 423 of `dkg.rs`): collecting commitment hashes from every other participant.
- **Round 3** (`wait_round_3`, line 515 of `dkg.rs`): collecting secret signing shares from every other participant.

The function body is:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;   // ← propagates on deser failure
    if seen.put(from) {
        messages.push((from, msg));
    }
}
``` [1](#0-0) 

`chan.recv` internally pops the first queued message for the given `(channel_tag, waitpoint)` key, then attempts `rmp_serde::decode::from_slice` on the payload. If decoding fails it returns `ProtocolError::DeserializationError`:

```rust
let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
    rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
Ok((from, decoded?))
``` [2](#0-1) 

The `?` in `recv_from_others` propagates this error immediately, aborting the entire `do_keyshare` future and therefore the DKG/reshare/refresh protocol for the honest party.

The `MessageBuffer` that backs the queue accepts any message from any participant without size or sender validation:

```rust
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
``` [3](#0-2) 

The `ProtocolExecutor::message()` entry point feeds every inbound network message directly into this buffer:

```rust
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
``` [4](#0-3) 

The channel tag for the shared channel (`ChannelTag::root_shared()`) is a fixed, publicly computable SHA-256 value. Waitpoints are assigned sequentially and deterministically by `next_waitpoint()`. A malicious participant who is part of the protocol therefore knows the exact `(channel_tag, waitpoint)` pair for `wait_round_1` and `wait_round_3` before those rounds begin.

**Contrast with echo broadcast.** The `reliable_broadcast_receive_all` function in `src/protocol/echo_broadcast.rs` explicitly handles deserialization failures by continuing the loop:

```rust
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,                              // ← graceful skip
};
``` [5](#0-4) 

`recv_from_others` provides no equivalent guard, making it the only message-collection path in the protocol that terminates fatally on a single malformed message.

The developers are aware that the message buffer accepts arbitrary injections; a test in `internal.rs` explicitly documents this:

```rust
fn attacker_can_fill_message_buffer_with_unused_waitpoints() {
    // Attacker injects messages for waitpoints the honest code never polls.
    comms.push_message(attacker, message);
    ...
    assert!(messages.len() == usize::try_from(attack_count).unwrap());
}
``` [6](#0-5) 

That test covers unused waitpoints; the gap is that no analogous protection exists for *active* waitpoints used by `recv_from_others`.

---

### Impact Explanation

A single malicious participant can abort DKG, reshare, or refresh for every honest party by sending one malformed message per attempt at `wait_round_1`. Because the attack costs only one network message per DKG invocation and can be repeated indefinitely, honest parties can never complete key generation as long as the malicious participant remains in the participant set. This constitutes **permanent denial of key generation, reshare, and refresh** for honest parties, matching the allowed High impact:

> *High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions.*

---

### Likelihood Explanation

- The attacker need only be a legitimate participant (no key leakage, no external compromise required).
- The correct `(channel_tag, waitpoint)` values are deterministic and publicly derivable from the participant list and protocol step count.
- Sending one malformed message per DKG attempt is trivially cheap.
- No timeout or exclusion mechanism is visible in the production code that would evict the malicious participant between attempts.

---

### Recommendation

Mirror the echo-broadcast pattern inside `recv_from_others`: skip messages that fail deserialization rather than propagating the error. A minimal fix:

```rust

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

**File:** src/protocol/internal.rs (L338-340)
```rust
        let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
            rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
        Ok((from, decoded?))
```

**File:** src/protocol/internal.rs (L512-514)
```rust
    fn message(&mut self, from: Participant, data: MessageData) {
        self.comms.push_message(from, data);
    }
```

**File:** src/protocol/internal.rs (L532-554)
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
    }
```

**File:** src/protocol/echo_broadcast.rs (L179-182)
```rust
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
```
