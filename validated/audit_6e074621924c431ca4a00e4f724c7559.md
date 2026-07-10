### Title
Inconsistent Error Handling for Unknown `from` in `reliable_broadcast_receive_all` Aborts DKG for Honest Parties — (`File: src/protocol/echo_broadcast.rs`)

### Summary

In `reliable_broadcast_receive_all`, the `MessageType::Send` branch propagates a fatal error via `?` when the message sender (`from`) is not in the participant list, while the `MessageType::Echo` and `MessageType::Ready` branches handle the same condition gracefully by silently skipping. A malicious participant or any entity that can inject a network message with a `from` value absent from the participant list can permanently abort the DKG (and therefore key generation, reshare, and refresh) for every honest party that receives the message.

### Finding Description

`reliable_broadcast_receive_all` in `src/protocol/echo_broadcast.rs` allocates a `state` vector of size `n = participants.len()` and processes incoming messages in a loop. The code already handles an out-of-bounds `sid` (session identifier from the message body) safely:

```rust
let Some(state_sid) = state.get_mut(sid) else {
    continue;   // gracefully skip
};
``` [1](#0-0) 

However, inside the `MessageType::Send` branch, the sender-identity check uses the `?` operator:

```rust
if state_sid.finish_send || sid != participants.index(from)? {
    continue;
}
``` [2](#0-1) 

`participants.index(from)` returns `Err(ProtocolError::InvalidIndex)` when `from` is not in the participant list:

```rust
pub fn index(&self, participant: Participant) -> Result<usize, ProtocolError> {
    self.indices
        .get(&participant)
        .copied()
        .ok_or(ProtocolError::InvalidIndex)
}
``` [3](#0-2) 

The `?` propagates this error out of `reliable_broadcast_receive_all`, terminating the entire async function. By contrast, the `Echo` and `Ready` branches call `seen_echo.put(from)` / `seen_ready.put(from)`, which return `false` for unknown participants and allow the loop to `continue` harmlessly:

```rust
if !state_sid.seen_echo.put(from) || state_sid.finish_echo {
    continue;
}
``` [4](#0-3) 

```rust
if !state_sid.seen_ready.put(from) || state_sid.finish_ready {
    continue;
}
``` [5](#0-4) 

`ParticipantCounter::put` is explicitly designed to return `false` for unknown participants:

```rust
pub fn put(&mut self, participant: Participant) -> bool {
    let i = match self.participants.indices.get(&participant) {
        None => return false,
        ...
    };
``` [6](#0-5) 

The `reliable_broadcast_receive_all` function is called by `do_broadcast`, which is the backbone of the DKG (`do_keyshare`), reshare, and refresh protocols. A fatal error here propagates all the way up and permanently aborts the protocol run for the affected honest party. [7](#0-6) 

### Impact Explanation

**High — Permanent denial of key generation, reshare, and refresh for honest parties.**

Every DKG, reshare, and refresh invocation passes through `do_broadcast` → `reliable_broadcast_receive_all`. A single injected `MessageType::Send` message whose `from` field is not in the participant list (but whose `sid` is a valid index 0 ≤ sid < n) causes the function to return `Err(ProtocolError::InvalidIndex)`, aborting the protocol for the receiving honest party. Because the attack can be repeated on every restart, the denial is effectively permanent.

### Likelihood Explanation

The `Protocol` trait's public `message(from: Participant, data: MessageData)` method accepts any `Participant` value without validating membership in the participant list before routing the message into the protocol state machine. The library's network-layer documentation states channels are authenticated but does not restrict senders to the declared participant set. A malicious coordinator (who controls message routing) or any entity that can deliver a single crafted message to an honest party's protocol instance can trigger this path. The attack requires only one well-formed `MessageType::Send` payload with a valid `sid` and an unknown `from`.

### Recommendation

Replace the fatal `?` with a graceful skip, consistent with how `Echo` and `Ready` branches handle unknown senders:

```rust
// Before (aborts on unknown from):
if state_sid.finish_send || sid != participants.index(from)? {
    continue;
}

// After (gracefully skips unknown from):
if state_sid.finish_send
    || participants.index(from).map_or(true, |i| sid != i)
{
    continue;
}
```

This makes the `Send` branch consistent with the `Echo` and `Ready` branches, which already use `put` to silently discard messages from unknown participants.

### Proof of Concept

1. Start a DKG with `n` honest participants.
2. Before the broadcast round completes, inject one message via `Protocol::message(from, data)` on any honest participant's protocol instance, where:
   - `from` = any `Participant` value not in the declared participant list (e.g., `Participant::from(9999u32)`)
   - `data` = a serialized `(sid, MessageType::Send(payload))` where `0 <= sid < n`
3. The honest participant's `reliable_broadcast_receive_all` reaches line 199, calls `participants.index(from)`, receives `Err(ProtocolError::InvalidIndex)`, and the `?` terminates the function.
4. The DKG fails for that participant. Repeating on every restart makes the denial permanent.

The existing test `test_malicious_sid_ignored` confirms that an out-of-bounds `sid` is safely ignored via `state.get_mut(sid)`, but there is no analogous test for an unknown `from` in the `Send` branch, leaving this inconsistency undetected. [8](#0-7)

### Citations

**File:** src/protocol/echo_broadcast.rs (L187-189)
```rust
        let Some(state_sid) = state.get_mut(sid) else {
            continue;
        };
```

**File:** src/protocol/echo_broadcast.rs (L199-201)
```rust
                if state_sid.finish_send || sid != participants.index(from)? {
                    continue;
                }
```

**File:** src/protocol/echo_broadcast.rs (L215-217)
```rust
                if !state_sid.seen_echo.put(from) || state_sid.finish_echo {
                    continue;
                }
```

**File:** src/protocol/echo_broadcast.rs (L268-270)
```rust
                if !state_sid.seen_ready.put(from) || state_sid.finish_ready {
                    continue;
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

**File:** src/protocol/echo_broadcast.rs (L602-635)
```rust
    #[test]
    fn test_malicious_sid_ignored() {
        let honest_participants = generate_participants(3);
        let dishonest_participant = Participant::from(3u32);
        let honest_votes = vec![true, true, true];

        // The broadcast_dishonest function returns a Result.
        // If the protocol panics, the test will fail.
        // If it returns Ok, it means the protocol completed.
        let result = broadcast_dishonest(
            &honest_participants,
            dishonest_participant,
            &honest_votes,
            do_broadcast_dishonest_consume_bad_sid,
        );

        // We expect the protocol to complete successfully.
        assert!(result.is_ok());

        let final_votes = result.unwrap();
        // The final votes should not be affected by the malicious message.

        // All participants should have the same view of the votes.
        for (p, v) in final_votes {
            let v_expected = vec![true, true, true, false];
            if p == dishonest_participant {
                // The dishonest participant might have a different view of its own vote
                // depending on when it processes its own message.
                // The important part is that it doesn't panic and that honest nodes agree.
            } else {
                assert_eq!(v, v_expected);
            }
        }
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

**File:** src/participants.rs (L310-313)
```rust
    pub fn put(&mut self, participant: Participant) -> bool {
        let i = match self.participants.indices.get(&participant) {
            None => return false,
            Some(&i) => i,
```
