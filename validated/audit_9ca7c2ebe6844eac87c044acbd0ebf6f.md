### Title
Single Malicious Participant Can Permanently Abort DKG/Reshare/Refresh via False Success Broadcast - (File: src/dkg.rs)

### Summary
The final round of the DKG/reshare/refresh protocol (`broadcast_success` in `src/dkg.rs`) requires **every** participant to reliably broadcast `(true, session_id)` and then asserts that all received votes are `true`. A single malicious participant who instead broadcasts `(false, session_id)` causes the unanimity check to fail for all honest parties, aborting the protocol after all cryptographic work is complete. Because the abort is delivered via the reliable echo broadcast, it is guaranteed to reach every honest party, making the denial permanent for any session that includes the malicious participant.

### Finding Description

`do_keyshare` in `src/dkg.rs` is the shared implementation of keygen, reshare, and refresh. Its final step (Round 5.4/5.5) calls `broadcast_success`:

```
// Step 5.4 and Step 5.5
broadcast_success(&mut chan, &participants, me, session_id).await?;
```

`broadcast_success` (lines 307–338) always broadcasts `(true, session_id)` for the honest caller and then collects all N participants' votes via `do_broadcast` (reliable echo broadcast). It then enforces a strict unanimity check:

```rust
if !vote_list.iter().all(|&(boolean, _)| boolean) {
    return Err(ProtocolError::AssertionFailed(
        "A participant seems to have failed its checks. Aborting Protocol!"
    ));
}
```

A malicious participant controls their own protocol implementation. Instead of calling `broadcast_success` (which hardcodes `true`), they call `do_broadcast` directly with `(false, session_id)`. The reliable echo broadcast (`do_broadcast` → `reliable_broadcast_send` + `reliable_broadcast_receive_all`) guarantees — by the Agreement and Totality properties of the echo broadcast protocol — that the `false` vote is delivered to every honest party. Every honest party then hits the `all(boolean)` check at line 329, which fails, and each returns `ProtocolError::AssertionFailed`, discarding the `KeygenOutput` they had already computed.

This abort occurs **after** all secret shares have been distributed and verified (lines 514–527), so the honest parties have done all the expensive cryptographic work and then are forced to discard the result.

The attack path is:
1. Malicious participant joins a keygen/reshare/refresh session as a normal participant (no privilege required).
2. Participates honestly through Rounds 1–5 to avoid early detection.
3. In Round 5.4, broadcasts `(false, session_id)` via the reliable broadcast channel.
4. Reliable broadcast guarantees all honest parties receive and accept this `false` vote.
5. All honest parties abort at line 329 of `src/dkg.rs`.
6. The malicious participant can repeat this in every subsequent session attempt, permanently blocking key generation or resharing as long as they remain in the participant set.

### Impact Explanation

**High — Permanent denial of key generation, reshare, and refresh for honest parties.**

All three operations (keygen, reshare, refresh) funnel through `do_keyshare` and terminate with `broadcast_success`. A single malicious participant within the documented BFT tolerance (`MaxFaulty = floor((N-1)/3)`) can abort every session indefinitely. If the malicious participant cannot be identified and excluded (the protocol error message names the aborting party only by the generic string "A participant seems to have failed", not by identity), honest parties have no way to complete key generation or key management operations. For reshare/refresh specifically, this means the existing key shares cannot be rotated, leaving the system permanently unable to perform key lifecycle management.

### Likelihood Explanation

Any participant in a DKG/reshare/refresh session can execute this attack with no cryptographic capability beyond normal protocol participation. The attacker needs only to be included in the participant list — a condition that is a prerequisite for legitimate participation. The attack requires no leaked keys, no network-level access, and no privileged role. It is trivially repeatable across every session attempt.

### Recommendation

Replace the strict unanimity check in `broadcast_success` with a threshold-based check: the protocol should succeed if at least `threshold` (or `N - MaxFaulty`) participants broadcast `true`. Participants who broadcast `false` should be identified by their session index (available from `vote_list`) and reported to the caller so they can be excluded from future sessions. This mirrors how the echo broadcast layer itself handles Byzantine faults — by tolerating up to `MaxFaulty` deviating parties rather than requiring unanimity.

### Proof of Concept

**Setup:** 4 participants (N=4, MaxFaulty=1), threshold=2. Participant P4 is malicious.

1. P1–P4 all participate honestly through Rounds 1–5 of `do_keyshare`.
2. P1–P3 call `broadcast_success`, which invokes `do_broadcast(chan, participants, me, (true, session_id))`.
3. P4 instead calls `do_broadcast(chan, participants, me, (false, session_id))` directly.
4. The reliable echo broadcast delivers P4's `(false, session_id)` to P1, P2, P3 with full Agreement guarantee.
5. Each of P1–P3 collects `vote_list = [(true, sid), (true, sid), (true, sid), (false, sid)]`.
6. The check `vote_list.iter().all(|&(boolean, _)| boolean)` at line 329 evaluates to `false`.
7. P1, P2, P3 each return `Err(ProtocolError::AssertionFailed("A participant seems to have failed its checks. Aborting Protocol!"))`.
8. `do_keyshare` returns `Err(...)` at line 531, discarding the computed `KeygenOutput`.
9. P4 repeats this in every subsequent session, permanently blocking keygen/reshare/refresh. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** src/dkg.rs (L529-537)
```rust

    // Step 5.4 and Step 5.5
    broadcast_success(&mut chan, &participants, me, session_id).await?;

    // Return the key pair
    Ok(KeygenOutput {
        private_share: SigningShare::new(my_signing_share),
        public_key: verifying_key,
    })
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
