### Title
Unauthenticated Sender in `reliable_broadcast_receive_all` Aborts DKG/Reshare/Refresh via `ProtocolError::InvalidIndex` - (File: src/protocol/echo_broadcast.rs)

### Summary

`reliable_broadcast_receive_all` propagates a fatal error when it receives a `MessageType::Send` message whose `from` participant is not in the expected participant list. Because the `Protocol::message()` entry point accepts messages from any `Participant` without validating membership, a single injected message from an out-of-set sender permanently aborts every protocol that relies on `do_broadcast` — including DKG, reshare, and refresh.

### Finding Description

`reliable_broadcast_receive_all` handles three message variants. For `MessageType::Echo` and `MessageType::Ready`, unknown senders are silently dropped via `ParticipantCounter::put`, which returns `false` for any participant not in the list: [1](#0-0) 

For `MessageType::Send`, however, the code calls `participants.index(from)?`: [2](#0-1) 

`ParticipantList::index` returns `Err(ProtocolError::InvalidIndex)` for any participant not in the list: [3](#0-2) 

The `?` operator propagates this error all the way out of `reliable_broadcast_receive_all`, through `do_broadcast`, and into `do_keyshare`, aborting the entire protocol run.

The `Protocol::message()` entry point — the public surface through which the library user delivers network messages — performs no membership check on `from`: [4](#0-3) 

Nor does `push_message`: [5](#0-4) 

`do_broadcast` is called three times inside `do_keyshare` (session-ID exchange, commitment broadcast, and success vote), so any one of these calls failing terminates the whole DKG/reshare/refresh: [6](#0-5) [7](#0-6) [8](#0-7) 

### Impact Explanation

A single `MessageType::Send` message delivered via `Protocol::message()` with a `from` value absent from the participant list causes `ProtocolError::InvalidIndex` to propagate and permanently abort the in-progress DKG, reshare, or refresh session. All honest parties must restart from scratch. If the attacker repeats the injection on every new session, key generation or resharing can be denied indefinitely.

This matches the allowed impact: **High — Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions.**

### Likelihood Explanation

The `Protocol` trait is the library's public API. Any host application that forwards received network messages to `protocol.message()` without pre-filtering by participant set — a natural and undocumented-as-unsafe usage — is vulnerable. In a permissionless P2P network, any node can send a message to any other node, making this trivially reachable. The attacker does not need any cryptographic material; only the ability to send one well-formed message to a target participant.

### Recommendation

Replace the `?` propagation with a graceful `continue` for unknown senders in the `MessageType::Send` branch of `reliable_broadcast_receive_all`:

```rust
// Before (aborts on unknown sender):
if state_sid.finish_send || sid != participants.index(from)? {
    continue;
}

// After (ignores unknown sender, consistent with Echo/Ready handling):
let Ok(from_idx) = participants.index(from) else {
    continue;
};
if state_sid.finish_send || sid != from_idx {
    continue;
}
```

Additionally, consider validating `from` membership at the `Protocol::message()` entry point and documenting the expected invariant.

### Proof of Concept

1. Honest participants `[P0, P1, P2]` start `keygen`. Each calls `do_broadcast` for the session-ID exchange round.
2. An attacker (participant `P99`, not in the list) sends a raw `MessageType::Send` message to `P0` at the correct waitpoint.
3. `P0`'s host application calls `protocol.message(P99, data)`. The message is buffered without validation.
4. Inside `reliable_broadcast_receive_all`, `chan.recv(wait).await` returns `(P99, (sid, MessageType::Send(...)))`.
5. `participants.index(P99)` returns `Err(ProtocolError::InvalidIndex)`.
6. The `?` propagates the error out of `reliable_broadcast_receive_all` → `do_broadcast` → `do_keyshare` → `do_keygen`.
7. `P0`'s protocol instance returns an error; the DKG session is permanently aborted for `P0`.
8. Repeating this on every new session prevents key generation from ever completing.

### Citations

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

**File:** src/protocol/echo_broadcast.rs (L212-216)
```rust
            MessageType::Echo(data) => {
                // skip if I received echo message from the sender in a specific session (sid)
                // or if I had already passed to the ready phase in this same session
                if !state_sid.seen_echo.put(from) || state_sid.finish_echo {
                    continue;
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

**File:** src/dkg.rs (L362-362)
```rust
    let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;
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

**File:** src/dkg.rs (L531-531)
```rust
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```
