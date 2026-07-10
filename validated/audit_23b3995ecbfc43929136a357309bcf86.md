### Title
Malicious Participant Can Permanently Block DKG, Reshare, and Refresh Completion via False Success Vote - (File: src/dkg.rs)

### Summary
The `broadcast_success` function in `src/dkg.rs` requires **unanimous** success votes from all `n` participants to finalize DKG, reshare, and refresh. A single malicious participant can broadcast `(false, session_id)` in this final round to permanently abort the protocol for all honest parties — even after all shares have been correctly distributed and verified in every preceding round.

### Finding Description
`broadcast_success` is the final step of `do_keyshare`, called at line 531 after all secret shares have been sent, received, and validated:

```rust
broadcast_success(&mut chan, &participants, me, session_id).await?;
```

The function always broadcasts `(true, session_id)` and then enforces a unanimous check:

```rust
let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
...
if !vote_list.iter().all(|&(boolean, _)| boolean) {
    return Err(ProtocolError::AssertionFailed(
        "A participant seems to have failed its checks. Aborting Protocol!"
    ));
}
```

A malicious participant who controls their own protocol implementation can deviate and send `(false, session_id)` as their `MessageType::Send` payload in this round. The underlying `do_broadcast` / `reliable_broadcast_receive_all` echo-broadcast protocol faithfully delivers this `false` vote to all honest participants. The unanimous check at line 329 then causes every honest participant to return `Err`, permanently aborting the DKG/reshare/refresh.

The structural parallel to the original report is exact:
- **Original**: A kick proposal succeeds, but the target drains the vault so `actionKick` throws and the eviction never executes.
- **Analog**: All DKG rounds succeed and shares are verified, but a malicious participant broadcasts `false` in the final confirmation round so `broadcast_success` throws and the key generation never completes.

In both cases, a critical, already-decided state transition is blocked by the target of that transition controlling a single blocking condition.

### Impact Explanation
**High — Permanent denial of key generation, reshare, and refresh for honest parties.**

All three protocols (`do_keygen`, `do_reshare`, and the refresh path) converge on `do_keyshare`, which calls `broadcast_success` as its terminal step. A single malicious participant can abort any of these protocols at will, indefinitely. Honest participants cannot retry without re-running all preceding rounds, and the malicious participant can repeat the attack on every attempt. The malicious participant also receives all honest parties' secret shares in the preceding rounds before triggering the abort, gaining information while denying the honest parties a usable key.

### Likelihood Explanation
Any participant who is willing to deviate from the protocol (e.g., a participant who wants to prevent a reshare that would remove them, or a participant who wants to stall key generation) can trivially trigger this. No cryptographic capability is required — only the ability to send a single bit (`false`) in the final broadcast round. The attack is reachable by any participant in any DKG, reshare, or refresh session.

### Recommendation
Remove the unanimous success-vote requirement. The `broadcast_success` function should not abort if a single participant votes `false`. Instead:
1. **Identify and exclude the malicious participant** by collecting votes and proceeding if a threshold of honest participants voted `true`, or
2. **Remove the final success-broadcast round entirely** — by the time `broadcast_success` is called, all shares have already been validated via `validate_received_share` and `verify_proof_of_knowledge`. The success broadcast adds no cryptographic guarantee and only introduces a new denial-of-service surface.

### Proof of Concept
1. Honest participants `P1, P2, P3` and malicious participant `M` run `do_keygen` with threshold 2.
2. All four participants complete rounds 1–5 of `do_keyshare` honestly: session IDs are exchanged, commitments broadcast, proofs verified, and secret shares distributed and validated.
3. In the `broadcast_success` round (line 531), `M` sends `MessageType::Send((false, session_id))` instead of `(true, session_id)`.
4. The echo-broadcast protocol in `reliable_broadcast_receive_all` faithfully delivers `M`'s `false` vote to `P1`, `P2`, and `P3`.
5. Each honest participant's `vote_list` contains `(false, session_id)` for `M`.
6. The check `vote_list.iter().all(|&(boolean, _)| boolean)` at line 329 evaluates to `false`.
7. All honest participants return `Err(ProtocolError::AssertionFailed(...))` — DKG is permanently aborted.
8. `M` can repeat this on every retry, indefinitely preventing key generation. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** src/dkg.rs (L529-532)
```rust

    // Step 5.4 and Step 5.5
    broadcast_success(&mut chan, &participants, me, session_id).await?;

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
