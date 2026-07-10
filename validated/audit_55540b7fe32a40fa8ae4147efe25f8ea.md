### Title
Any Single Participant Refusal Permanently Stalls DKG, Reshare, and Refresh — (File: src/protocol/helpers.rs)

### Summary
`recv_from_others` unconditionally waits for **all N** participants to respond before any protocol round can advance. Because the DKG, reshare, and refresh protocols call this function for every round-trip exchange, a single malicious or unresponsive participant can permanently block key generation for all honest parties. No timeout, no threshold-based fallback, and no exclusion mechanism exists in the library to let the remaining T-of-N honest participants proceed.

### Finding Description
`recv_from_others` in `src/protocol/helpers.rs` loops on `while !seen.full()`, where `full()` is only true when every participant in the list has contributed exactly one message:

```rust
// src/protocol/helpers.rs  lines 19-24
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

`seen.full()` delegates to `ParticipantCounter::full()` in `src/participants.rs` (line 329), which returns `true` only when `self.counter == 0`, i.e., every participant has been seen. There is no escape path if one participant never sends.

`do_keyshare` in `src/dkg.rs` calls `recv_from_others` twice:

1. **Round 1 – commitment hashes** (lines 422–426): every participant must deliver their hash commitment before the round advances.
2. **Round 5 – secret shares** (lines 514–528): every participant must deliver their Shamir share before the signing share can be assembled.

Additionally, `do_broadcast` / `reliable_broadcast_receive_all` in `src/protocol/echo_broadcast.rs` terminates only when **all N** broadcast sessions have reached the Ready phase (line 323):

```rust
if state.iter().all(|x| x.finish_ready) {
    return Ok(vote_output);
}
```

If participant A never sends its `Send` message, `state[A].finish_ready` stays `false` forever, and the loop never exits. The early-abort amplification check (lines 241–263) only fires during the Echo phase; it has no analogue for the Send phase.

`broadcast_success` in `src/dkg.rs` (lines 307–338) calls `do_broadcast` as the final DKG step, so even a participant that cooperated through all earlier rounds can abort the entire protocol at the last moment by going silent here.

The same structural dependency propagates to `do_reshare` and the refresh path (both call `do_keyshare`).

### Impact Explanation
**High — Permanent denial of key generation, reshare, and refresh for honest parties.**

Any single participant in the protocol set can halt DKG, reshare, or refresh indefinitely by simply not sending one message at any round. Because the library provides no timeout, no threshold-based continuation, and no mechanism to expel a silent participant and restart with the remaining quorum, honest parties are left waiting forever. The master public key is never produced (or never refreshed), making the entire threshold-signing system unusable. This directly matches the allowed impact: *"Permanent denial of … key generation, reshare, refresh … for honest parties under valid protocol inputs and documented trust assumptions."*

### Likelihood Explanation
**Medium.** Every participant in the protocol is a potential attacker. The attack requires no cryptographic capability — only the ability to drop outgoing messages at a chosen round. A participant who has already received others' secret shares (Round 5) but then goes silent has additionally learned partial key material while preventing the honest parties from completing their own shares. The attack is trivially repeatable across every DKG/reshare/refresh attempt.

### Recommendation
1. **Introduce a round timeout** at the `recv_from_others` and `reliable_broadcast_receive_all` layers. After the timeout, identify which participants have not responded and propagate their identities as `ProtocolError::MaliciousParticipant` so callers can restart with a reduced set.
2. **Allow threshold-based termination** in `reliable_broadcast_receive_all`: once `2t + 1` sessions have completed the Ready phase (where `t` is the Byzantine threshold), treat the remaining sessions as belonging to faulty parties and return a partial map rather than blocking.
3. **Document the liveness assumption** explicitly: if the design intentionally requires all N participants, state this in the public API so callers know they must implement their own watchdog and participant-exclusion logic before retrying.

### Proof of Concept

```
Setup: N=3 participants P0, P1, P2; threshold T=2.

1. P0, P1, P2 all call `keygen()` → `do_keygen()` → `do_keyshare()`.
2. Round 1: P0 and P1 send their commitment hashes; P2 silently drops its message.
3. `recv_from_others` on P0 and P1 loops forever at line 19 of helpers.rs:
       while !seen.full() { ... }   // seen.full() never becomes true
4. No timeout fires. No error is returned. The DKG never completes.
5. P0 and P1 are permanently denied their KeygenOutput.

Variant: P2 cooperates through Round 4 (receiving all secret shares),
then drops its Round 5 share message and its broadcast_success message.
P0 and P1 still block forever, while P2 has already accumulated
partial share material from the earlier rounds.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** src/protocol/helpers.rs (L6-26)
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
```

**File:** src/participants.rs (L328-331)
```rust
    /// Check if this counter contains all participants
    pub fn full(&self) -> bool {
        self.counter == 0
    }
```

**File:** src/dkg.rs (L307-338)
```rust
async fn broadcast_success(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    session_id: HashOutput,
) -> Result<(), ProtocolError> {
    // broadcast node me succeded
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
    // unwrap here would never fail as the broadcast protocol ends only when the map is full
    let vote_list = vote_list
        .into_vec_or_none()
        .ok_or_else(|| ProtocolError::AssertionFailed("vote_list is empty".to_string()))?;
    // go through all the list of votes and check if any is fail or some does not contain the session id

    if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
        return Err(ProtocolError::AssertionFailed(
            "A participant
                broadcast the wrong session id. Aborting Protocol!"
                .to_string(),
        ));
    }

    if !vote_list.iter().all(|&(boolean, _)| boolean) {
        return Err(ProtocolError::AssertionFailed(
            "A participant
                seems to have failed its checks. Aborting Protocol!"
                .to_string(),
        ));
    }
    // Wait for all the tasks to complete
    Ok(())
}
```

**File:** src/dkg.rs (L422-426)
```rust
    for (from, their_commitment_hash) in
        recv_from_others(&chan, wait_round_1, &participants, me).await?
    {
        all_hash_commitments.put(from, their_commitment_hash);
    }
```

**File:** src/dkg.rs (L514-528)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        // Step 5.3
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
    }
```

**File:** src/protocol/echo_broadcast.rs (L320-326)
```rust
                    // if all the ready slots are set to true
                    // then all sessions have ended successfully
                    // we can thus output that the n instances of the broadcast protocols have succeeded
                    if state.iter().all(|x| x.finish_ready) {
                        return Ok(vote_output);
                    }
                }
```
