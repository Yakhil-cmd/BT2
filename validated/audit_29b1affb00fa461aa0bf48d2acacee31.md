### Title
Unhandled `InvalidIndex` Error in `reliable_broadcast_receive_all` Permanently Aborts DKG, Reshare, and Refresh — (File: `src/protocol/echo_broadcast.rs`)

---

### Summary

`reliable_broadcast_receive_all` uses the `?` operator on `participants.index(from)` inside a message-processing loop. When a message arrives whose `from` field is not in the participant list, the function returns a hard error instead of skipping the message. Because `do_broadcast` calls this function, and `do_keyshare` calls `do_broadcast` multiple times, any such message permanently aborts DKG, reshare, and refresh for all honest parties.

---

### Finding Description

Inside `reliable_broadcast_receive_all`, the main loop receives messages and dispatches on their type. In the `MessageType::Send` arm the code checks whether the sender's network identity matches the session-ID they claim: [1](#0-0) 

```rust
match vote.clone() {
    MessageType::Send(data) => {
        if state_sid.finish_send || sid != participants.index(from)? {
            continue;
        }
```

`participants.index(from)` returns `Err(ProtocolError::InvalidIndex)` whenever `from` is absent from the participant list. The `?` operator propagates that error out of `reliable_broadcast_receive_all`, terminating the function immediately.

The intent of the guard is to *skip* messages from unexpected senders (the `continue` branch). The `?` turns a "skip this message" condition into a fatal protocol abort.

The message buffer (`push_message`) performs no validation of the `from` field before storing a message: [2](#0-1) 

```rust
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
```

A message injected with any `Participant` value not in the session's list is buffered without rejection. When the loop later calls `chan.recv(wait).await` and receives that message, `from` is the injected value, and `participants.index(from)?` aborts the broadcast.

`do_broadcast` wraps `reliable_broadcast_receive_all` and propagates its result: [3](#0-2) 

`do_keyshare` calls `do_broadcast` at two separate points (session-ID exchange and commitment exchange): [4](#0-3) [5](#0-4) 

`do_keygen`, `do_reshare`, and the refresh path all call `do_keyshare`: [6](#0-5) [7](#0-6) 

A single injected message with an unknown `from` therefore permanently kills DKG, reshare, or refresh for every honest participant running that session.

The existing test in `internal.rs` explicitly acknowledges that an attacker can inject messages into the buffer using an arbitrary `Participant` value: [8](#0-7) 

---

### Impact Explanation

**High — Permanent denial of key generation, reshare, and refresh for honest parties.**

Once `reliable_broadcast_receive_all` returns an error, `do_broadcast` returns that error, `do_keyshare` returns that error, and the entire DKG/reshare/refresh session is unrecoverably aborted. Honest parties cannot complete the protocol and must restart from scratch. A single malicious message is sufficient; the attacker does not need to be a registered participant.

---

### Likelihood Explanation

The `message(from, data)` entry point on the `Protocol` trait is the standard way for the host application to deliver network messages. The library places no restriction on the `from` value at that layer. Any network-adjacent adversary — a participant not in the current session, a relay node, or a message-injecting attacker — can supply an out-of-set `from` value. The triggering condition (one `MessageType::Send` message with an unknown sender delivered during the broadcast round) is trivially achievable.

---

### Recommendation

Replace the propagating `?` with a graceful skip so that messages from unknown senders are silently ignored, matching the stated intent of the guard:

```rust
// Before (aborts the entire broadcast on unknown sender)
if state_sid.finish_send || sid != participants.index(from)? {
    continue;
}

// After (skips the message, continues the loop)
let Ok(from_index) = participants.index(from) else {
    continue;
};
if state_sid.finish_send || sid != from_index {
    continue;
}
``` [9](#0-8) 

---

### Proof of Concept

1. Initiate a DKG session among participants `[P0, P1, P2]`.
2. Before the broadcast round completes, call `protocol.message(P99, crafted_send_message)` on any honest participant, where `P99` is not in `[P0, P1, P2]` and `crafted_send_message` is a valid `MessageType::Send` payload for the broadcast waitpoint.
3. The honest participant's `reliable_broadcast_receive_all` loop receives the message, reaches `participants.index(P99)?`, gets `Err(ProtocolError::InvalidIndex)`, and returns that error.
4. `do_broadcast` → `do_keyshare` → `do_keygen` all return the same error.
5. The DKG session is permanently aborted; no key material is produced.

### Citations

**File:** src/protocol/echo_broadcast.rs (L191-205)
```rust
        match vote.clone() {
            // Receive send vote then echo to everybody
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

**File:** src/dkg.rs (L540-553)
```rust
pub async fn do_keygen<C: Ciphersuite>(
    chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    mut rng: impl CryptoRngCore,
) -> Result<KeygenOutput<C>, ProtocolError> {
    let threshold = threshold.into();
    // pick share at random
    let secret = SigningKey::<C>::new(&mut rng).to_scalar();
    // call keyshare
    let keygen_output =
        do_keyshare::<C>(chan, participants, me, threshold, secret, None, &mut rng).await?;
    Ok(keygen_output)
```

**File:** src/dkg.rs (L600-634)
```rust
pub async fn do_reshare<C: Ciphersuite>(
    chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    old_participants: ParticipantList,
    mut rng: impl CryptoRngCore,
) -> Result<KeygenOutput<C>, ProtocolError> {
    let threshold = threshold.into();
    let intersection = old_participants.intersection(&participants);
    // either extract the share and linearize it or set it to zero
    let secret = old_signing_key
        .map(|x_i| {
            intersection
                .lagrange::<C>(me)
                .map(|lambda| lambda * x_i.to_scalar())
        })
        .transpose()?
        .unwrap_or_else(<C::Group as Group>::Field::zero);

    let old_reshare_package = Some((old_public_key, old_participants));
    let keygen_output = do_keyshare::<C>(
        chan,
        participants,
        me,
        threshold,
        secret,
        old_reshare_package,
        &mut rng,
    )
    .await?;

    Ok(keygen_output)
```
