### Title
Single Malicious Participant Can Permanently Abort DKG/Reshare/Refresh via `broadcast_success` False Vote - (File: src/dkg.rs)

### Summary
The `broadcast_success` function in `src/dkg.rs` is the final gate of the DKG, reshare, and refresh protocols. It requires **all** N participants to broadcast `(true, session_id)`. Because the underlying echo broadcast guarantees agreement, a single malicious participant who broadcasts `(false, session_id)` causes every honest party to observe the false vote and abort — permanently denying key generation, reshare, or refresh for all honest parties, even when the number of malicious participants is within the documented `MaxFaulty = (N-1)/3` BFT threshold.

### Finding Description

`broadcast_success` is called as the very last step of `do_keyshare`, which backs `do_keygen`, `do_reshare`, and (via reshare) refresh:

```rust
// src/dkg.rs line 531
broadcast_success(&mut chan, &participants, me, session_id).await?;
```

Inside `broadcast_success`, every participant broadcasts `(true, session_id)` via `do_broadcast` (the echo broadcast), then the result is checked with a strict unanimity predicate:

```rust
// src/dkg.rs lines 329-335
if !vote_list.iter().all(|&(boolean, _)| boolean) {
    return Err(ProtocolError::AssertionFailed(
        "A participant
            seems to have failed its checks. Aborting Protocol!"
            .to_string(),
    ));
}
```

The echo broadcast protocol (`do_broadcast` / `reliable_broadcast_receive_all`) provides the **Agreement** property: if any honest party delivers a value, every honest party delivers the same value. This means a malicious participant who broadcasts `(false, session_id)` causes all honest parties to deliver `false` for that slot, triggering the `all(|&(boolean, _)| boolean)` check to fail for every honest party simultaneously.

The documented BFT threshold is `MaxFaulty = (N-1)/3` (e.g., 1 malicious party is within threshold for N=4). Yet `broadcast_success` requires unanimity across all N participants — a strictly stronger requirement than the BFT threshold. A single malicious participant, even one within the documented fault tolerance, can exploit this gap.

The attack path is:
1. Malicious participant joins DKG/reshare/refresh honestly through all earlier rounds (rounds 1–5 of `do_keyshare`), contributing valid commitments, proofs of knowledge, and secret shares.
2. In the final `broadcast_success` round, the malicious participant broadcasts `(false, session_id)` instead of `(true, session_id)`.
3. Due to echo broadcast agreement, all honest parties receive and deliver `false` for the malicious participant's slot.
4. The unanimity check fails for all honest parties; every honest party returns `ProtocolError::AssertionFailed`.
5. No key material is output. The protocol must be restarted, and the malicious participant can repeat this indefinitely.

### Impact Explanation

**High: Permanent denial of key generation, reshare, and refresh for honest parties under valid protocol inputs and documented trust assumptions.**

All three top-level protocols (`do_keygen`, `do_reshare`, and key refresh) call `do_keyshare`, which calls `broadcast_success` as its final step. A single malicious participant within the documented `MaxFaulty` bound can abort all three protocols indefinitely. No key material is ever produced or updated, and honest parties have no mechanism to exclude the malicious participant and retry within the same session.

### Likelihood Explanation

Any participant in a DKG, reshare, or refresh session can execute this attack. No special privilege is required beyond being a valid member of the participant list. The attacker can participate honestly through all expensive earlier rounds (to avoid early detection) and only deviate at the final, cheap broadcast step. The attack is repeatable across every session restart.

### Recommendation

Replace the unanimity check in `broadcast_success` with a threshold-based check that tolerates up to `MaxFaulty` false votes, consistent with the documented BFT assumption. Specifically:

- Count the number of `false` votes received.
- Abort only if the number of `false` votes exceeds `MaxFaulty = (N-1)/3`.
- Identify and log the specific participants who voted `false` so callers can exclude them from future sessions.

This mirrors the fix pattern from the external report: instead of requiring a single push to succeed (unanimity), use a pull/threshold model that tolerates the documented number of faults.

### Proof of Concept

With N=4 participants (MaxFaulty=1), participant P4 is malicious:

1. P1, P2, P3, P4 all run `do_keygen` through rounds 1–5 of `do_keyshare` honestly.
2. At line 531 of `src/dkg.rs`, `broadcast_success` is called.
3. P4 calls `do_broadcast` with `(false, session_id)` instead of `(true, session_id)`.
4. Echo broadcast agreement ensures P1, P2, P3 all deliver `(false, session_id)` for P4's slot.
5. The check at line 329 of `src/dkg.rs` (`vote_list.iter().all(|&(boolean, _)| boolean)`) evaluates to `false` for P1, P2, and P3.
6. All three honest parties return `ProtocolError::AssertionFailed("A participant seems to have failed its checks. Aborting Protocol!")`.
7. No `KeygenOutput` is produced. P4 repeats this in every subsequent session. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** src/protocol/echo_broadcast.rs (L67-78)
```rust
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    // case where no malicious parties are assumed: when n <= 3/
    // In this case the echo and ready thresholds are both 0
    // later we compare if we have collected more votes than these thresholds
    if n <= 3 {
        return (0, 0);
    }
    // we should always have n >= 3*threshold + 1
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
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
