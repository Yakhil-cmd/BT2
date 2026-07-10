### Title
Unvalidated `from` Participant in `reliable_broadcast_receive_all` Causes Protocol Termination via Error Propagation — (File: `src/protocol/echo_broadcast.rs`)

---

### Summary

`reliable_broadcast_receive_all` processes incoming `MessageType::Send` messages by calling `participants.index(from)?` to validate the sender's session index. If `from` is a `Participant` not present in the participant list, `participants.index()` returns `Err(ProtocolError::InvalidIndex)`, and the `?` operator propagates this error out of the entire function, aborting the DKG/broadcast protocol for the honest party. Because the library's `message()` entry point accepts any `Participant` value without prior membership validation, any caller — including a non-participant — can inject a single crafted `MessageType::Send` message to terminate an in-progress DKG, reshare, or refresh for any honest participant.

---

### Finding Description

The `Protocol::message()` trait method, implemented in `ProtocolExecutor`, accepts an arbitrary `from: Participant` and forwards it unconditionally into the message buffer: [1](#0-0) 

`push_message` performs no membership check — it only validates message length and header format: [2](#0-1) 

When the buffered message is later dequeued inside `reliable_broadcast_receive_all`, the `from` value is used directly in the `MessageType::Send` branch: [3](#0-2) 

`participants.index(from)` returns `Err(ProtocolError::InvalidIndex)` when `from` is absent from the list: [4](#0-3) 

The `?` on line 199 of `echo_broadcast.rs` propagates this error out of `reliable_broadcast_receive_all`, which is called by `do_broadcast`, which is called by `do_keyshare` (the core of DKG, reshare, and refresh): [5](#0-4) 

By contrast, the `MessageType::Echo` and `MessageType::Ready` branches use `ParticipantCounter::put(from)`, which silently returns `false` for unknown participants and is therefore safe: [6](#0-5) 

The `MessageType::Send` branch is the only one that uses `?` on a participant lookup, making it the sole exploitable path.

---

### Impact Explanation

A single injected `MessageType::Send` message with a valid `sid` (any value in `0..n`) and a `from` participant not in the participant list causes `reliable_broadcast_receive_all` to return `Err(ProtocolError::InvalidIndex)`. This unwinds `do_broadcast`, then `do_keyshare`, aborting DKG, reshare, or refresh for the targeted honest participant. Because the attacker can repeat this injection on every protocol restart, the denial is persistent. This matches the **High** impact class: permanent denial of key generation, reshare, or refresh for honest parties.

---

### Likelihood Explanation

The `Protocol::message()` function is the public API surface for delivering network messages. The library imposes no restriction on which `Participant` value the caller may supply as `from`. Any party that can deliver a message to an honest participant's protocol instance — including a non-participant adversary — can trigger this with a single message. No cryptographic material or privileged access is required; only the ability to call `message()` with a crafted payload.

---

### Recommendation

In the `MessageType::Send` branch of `reliable_broadcast_receive_all`, replace the error-propagating lookup with a membership guard that skips unknown senders instead of aborting:

```rust
MessageType::Send(data) => {
    // Guard: skip messages from participants not in the list
    let Ok(expected_sid) = participants.index(from) else {
        continue;
    };
    if state_sid.finish_send || sid != expected_sid {
        continue;
    }
    // ... rest of send handling
}
```

This mirrors the pattern already used correctly in the `Echo` and `Ready` branches, where `ParticipantCounter::put(from)` returns `false` for unknown participants and the message is silently skipped.

---

### Proof of Concept

1. An honest set of participants begins DKG. Each participant's protocol instance is running `reliable_broadcast_receive_all` inside `do_broadcast` (called from `do_keyshare`).
2. An attacker (not in the participant list) constructs a raw message whose payload deserializes as `(sid, MessageType::Send(data))` with `sid = 0` (a valid index).
3. The attacker calls `honest_participant_protocol.message(attacker_participant, crafted_bytes)` where `attacker_participant` is any `Participant` value absent from the participant list.
4. The message is buffered unconditionally by `push_message`.
5. When the honest participant's async loop dequeues this message, it enters the `MessageType::Send` branch and evaluates `participants.index(attacker_participant)?`.
6. `participants.index()` returns `Err(ProtocolError::InvalidIndex)`; the `?` propagates it out of `reliable_broadcast_receive_all`, out of `do_broadcast`, and out of `do_keyshare`.
7. The honest participant's DKG fails. The attacker repeats on every restart, achieving persistent denial of key generation.

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

**File:** src/protocol/internal.rs (L512-514)
```rust
    fn message(&mut self, from: Participant, data: MessageData) {
        self.comms.push_message(from, data);
    }
```

**File:** src/protocol/echo_broadcast.rs (L193-201)
```rust
            MessageType::Send(data) => {
                // If the sender is not the one identified by the session id (sid)
                // or if the sender have already delivered a MessageType::Send message
                // then skip.
                // The second condition prevents a malicious party starting the protocol
                // on behalf on somebody else
                if state_sid.finish_send || sid != participants.index(from)? {
                    continue;
                }
```

**File:** src/protocol/echo_broadcast.rs (L212-219)
```rust
            MessageType::Echo(data) => {
                // skip if I received echo message from the sender in a specific session (sid)
                // or if I had already passed to the ready phase in this same session
                if !state_sid.seen_echo.put(from) || state_sid.finish_echo {
                    continue;
                }
                // insert or increment the number of collected echo of a specific vote
                state_sid.data_echo.insert_or_increase_counter(data.clone());
```

**File:** src/participants.rs (L135-140)
```rust
    pub fn index(&self, participant: Participant) -> Result<usize, ProtocolError> {
        self.indices
            .get(&participant)
            .copied()
            .ok_or(ProtocolError::InvalidIndex)
    }
```

**File:** src/dkg.rs (L435-441)
```rust
    let commitments_and_proofs_map = do_broadcast(
        &mut chan,
        &participants,
        me,
        (commitment, proof_of_knowledge),
    )
    .await?;
```
