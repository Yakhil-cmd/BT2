### Title
Malicious Participant Injects Unknown-Sender Message to Permanently Abort DKG/Reshare/Refresh via Unguarded `?` in Echo-Broadcast - (File: src/protocol/echo_broadcast.rs)

### Summary

In `reliable_broadcast_receive_all`, the `MessageType::Send` arm uses `participants.index(from)?` with the `?` operator to check whether the message sender matches the session ID. If `from` is any `Participant` value not present in the participant list, `participants.index` returns `Err(ProtocolError::InvalidIndex)` and the `?` propagates that error out of the entire async function, aborting the protocol. Because `do_broadcast` (which calls this function) is invoked multiple times inside `do_keyshare`, a single injected message from an unknown sender permanently kills DKG, reshare, or refresh for every honest party waiting on that broadcast round.

### Finding Description

**Root cause — wrong error-propagation operator in a skip-guard:** [1](#0-0) 

```rust
MessageType::Send(data) => {
    if state_sid.finish_send || sid != participants.index(from)? {
        continue;
    }
```

The comment above this block says the intent is to *skip* messages where the sender does not match the session ID. The `Echo` and `Ready` arms implement exactly that pattern — they call `state_sid.seen_echo.put(from)` which silently returns `false` for unknown participants and falls through to `continue`. The `Send` arm instead calls `participants.index(from)?`, which propagates `Err(ProtocolError::InvalidIndex)` out of the function the moment `from` is not in the list. [2](#0-1) 

```rust
pub fn index(&self, participant: Participant) -> Result<usize, ProtocolError> {
    self.indices
        .get(&participant)
        .copied()
        .ok_or(ProtocolError::InvalidIndex)   // ← returns Err for unknown participant
}
```

**Call chain to DKG:**

`do_keyshare` calls `do_broadcast` twice (session-ID broadcast and commitment/proof broadcast): [3](#0-2) [4](#0-3) 

`do_broadcast` calls `reliable_broadcast_receive_all`: [5](#0-4) 

**Message injection path:**

The protocol framework's `message` entry point accepts any `(Participant, MessageData)` pair without validating that `from` belongs to the participant list: [6](#0-5) 

```rust
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
```

`push_message` only validates the message header format, not the sender identity: [7](#0-6) 

A malicious participant (or a coordinator routing messages on their behalf) constructs a raw message whose `MessageHeader` matches the active broadcast `waitpoint` and whose body deserializes as `MessageType::Send(...)` with any valid `sid` in `[0, n)`. They set `from` to any `Participant` value outside the agreed participant list. When an honest party's `reliable_broadcast_receive_all` loop dequeues this message and reaches the `Send` arm, `participants.index(from)?` returns `Err(ProtocolError::InvalidIndex)`, the `?` propagates it, and the function returns an error — aborting the entire DKG/reshare/refresh protocol for that honest party.

The existing test in the repository explicitly demonstrates that arbitrary `from` values and arbitrary waitpoints can be injected with no filtering: [8](#0-7) 

### Impact Explanation

Every call to `do_keygen`, `do_reshare`, or `do_refresh` passes through `do_keyshare` → `do_broadcast` → `reliable_broadcast_receive_all`. A single crafted message from an unknown sender aborts the broadcast round with a hard error, making it impossible for honest parties to complete key generation, resharing, or refresh. There is no retry or recovery path — the protocol must be restarted from scratch, and the attacker can repeat the injection indefinitely.

**Impact category:** High — Permanent denial of key generation, reshare, and refresh for honest parties under valid protocol inputs.

### Likelihood Explanation

Any participant in the protocol who can influence the `from` field passed to `protocol.message(from, data)` — including a malicious coordinator or a malicious participant who controls their own network-layer identity — can trigger this with a single message. No cryptographic material, no privileged keys, and no prior protocol state are required. The attacker only needs to know the broadcast `waitpoint` value, which is deterministic and publicly derivable from the channel-tag construction.

### Recommendation

Replace the error-propagating `?` with a soft skip that matches the intent of the guard and the behavior of the `Echo`/`Ready` arms:

```rust
MessageType::Send(data) => {
    // Resolve sender index; silently skip if sender is unknown.
    let Ok(from_idx) = participants.index(from) else {
        continue;
    };
    if state_sid.finish_send || sid != from_idx {
        continue;
    }
    // ... rest of Send handling
```

This makes an unknown `from` value a no-op (identical to how `seen_echo.put(from)` handles unknown participants in the `Echo` arm) rather than a fatal error.

### Proof of Concept

1. Start a DKG session with participants `[P0, P1, P2]` and threshold 2.
2. Before any honest party completes the first `do_broadcast` round, inject one message via `protocol.message(from=Participant(9999), data)` where `data` is a correctly-framed `MessageType::Send(...)` payload with `sid=0` and the correct broadcast `waitpoint` header.
3. Observe that the honest party's `reliable_broadcast_receive_all` returns `Err(ProtocolError::InvalidIndex)` immediately.
4. The DKG protocol for that party is permanently aborted; no key material is produced.
5. Repeat for every honest party to deny the entire key generation ceremony.

### Citations

**File:** src/protocol/echo_broadcast.rs (L193-210)
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
                vote = MessageType::Echo(data);
                // upon receiving a send message, echo it
                chan.send_many(wait, &(&sid, &vote))?;
                state_sid.finish_send = true;

                // simulate an echo vote sent by me
                is_simulated_vote = true;
                from = me;
            }
```

**File:** src/protocol/echo_broadcast.rs (L334-348)
```rust
pub async fn do_broadcast<'a, T>(
    chan: &mut SharedChannel,
    participants: &'a ParticipantList,
    me: Participant,
    data: T,
) -> Result<ParticipantMap<'a, T>, ProtocolError>
where
    T: Serialize + Clone + DeserializeOwned + PartialEq,
{
    let wait_broadcast = chan.next_waitpoint();
    let send_vote = reliable_broadcast_send(chan, wait_broadcast, participants, me, data)?;
    let vote_list =
        reliable_broadcast_receive_all(chan, wait_broadcast, participants, me, send_vote).await?;
    Ok(vote_list)
}
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
