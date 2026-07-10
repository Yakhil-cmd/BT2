### Title
Single Malicious Participant Can Abort DKG/Reshare/Refresh for All Honest Parties via `broadcast_success` Final-Round Veto - (File: src/dkg.rs)

### Summary
The `broadcast_success` function at the end of every DKG, reshare, and refresh run requires **all** `N` participants to reliably broadcast `(true, session_id)`. A single malicious participant within the documented `⌊(N−1)/3⌋` fault tolerance can instead broadcast `(false, session_id)`, causing every honest party to receive a failure signal and abort with a `ProtocolError`. Because the malicious party can repeat this veto on every subsequent attempt, honest parties are permanently denied key generation, resharing, and refresh under valid protocol inputs.

### Finding Description

`broadcast_success` is called unconditionally as the last step of `do_keyshare`, which backs `do_keygen`, `do_reshare`, and the refresh path:

```
src/dkg.rs line 531:
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```

The function body:

```rust
// src/dkg.rs lines 307–338
async fn broadcast_success(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    session_id: HashOutput,
) -> Result<(), ProtocolError> {
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
    let vote_list = vote_list
        .into_vec_or_none()
        .ok_or_else(|| ...)?;

    if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
        return Err(ProtocolError::AssertionFailed(
            "A participant broadcast the wrong session id. Aborting Protocol!",
        ));
    }

    if !vote_list.iter().all(|&(boolean, _)| boolean) {   // ← unanimous check
        return Err(ProtocolError::AssertionFailed(
            "A participant seems to have failed its checks. Aborting Protocol!",
        ));
    }
    Ok(())
}
```

`do_broadcast` uses the authenticated double-echo reliable broadcast (`echo_broadcast.rs`). The reliable broadcast guarantees that every honest party receives **the same** value from each sender, even with up to `⌊(N−1)/3⌋` malicious parties. Therefore, if a malicious participant `M` broadcasts `(false, session_id)`, every honest party's `vote_list` will contain `(false, session_id)` for `M`, and the `.all(|&(boolean, _)| boolean)` predicate fails for every honest party simultaneously.

The attacker's entry path is straightforward:
1. Participate honestly through all five DKG rounds (session-ID broadcast, commitment hash, commitment + PoK broadcast, share distribution, share verification).
2. In the final `broadcast_success` round, broadcast `(false, session_id)` instead of `(true, session_id)`.
3. The reliable broadcast delivers this to all honest parties; every honest party hits the `Err` branch and discards its freshly computed key share.
4. Repeat on every restart attempt.

No cryptographic material needs to be leaked; the attacker only needs to be a legitimate participant.

### Impact Explanation

Every honest party aborts `do_keyshare` and discards its output. Because the malicious party can repeat the veto on every subsequent DKG/reshare/refresh invocation, honest parties are **permanently** denied key generation, resharing, and refresh. This maps directly to:

> **High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions.**

The README explicitly states the protocol tolerates `⌊N/3⌋` malicious parties, yet a single malicious party — well within that bound for any `N ≥ 3` — can veto every run.

### Likelihood Explanation

Any participant who wishes to block key generation (e.g., a competitor, a censoring node, or a participant whose share was about to be rotated out via reshare) can execute this with zero cryptographic capability. The attack requires only the ability to send a single crafted message in the final broadcast round, which is a normal protocol action. Likelihood is **high** whenever a participant has an incentive to prevent key generation from completing.

### Recommendation

Replace the unanimous success check with a threshold-based check. Collect the `broadcast_success` votes and proceed if at least `N − ⌊(N−1)/3⌋` parties broadcast `(true, session_id)`. Parties that broadcast `false` or a wrong session ID should be identified and excluded from the output participant set (or flagged for the caller), but their presence should not abort the protocol for honest parties. This aligns the final-round liveness guarantee with the `⌊(N−1)/3⌋` fault-tolerance claim made throughout the documentation.

### Proof of Concept

Setup: `N = 4`, threshold `= 2`, one malicious participant `M = P3`.

1. `P0`, `P1`, `P2`, `P3` all run `keygen`. `P3` participates honestly through rounds 1–5 (session-ID broadcast, commitment hash, commitment + PoK, share distribution, share verification).
2. In the `broadcast_success` round, `P3` calls `do_broadcast` with `(false, session_id)` instead of `(true, session_id)`.
3. The reliable broadcast delivers `(false, session_id)` from `P3` to `P0`, `P1`, `P2`.
4. Each of `P0`, `P1`, `P2` evaluates `vote_list.iter().all(|&(boolean, _)| boolean)` → `false` (because `P3`'s entry is `false`) and returns `Err(ProtocolError::AssertionFailed("A participant seems to have failed its checks. Aborting Protocol!"))`.
5. All three honest parties discard their key shares. `P3` repeats on every subsequent attempt, permanently blocking key generation. [1](#0-0) [2](#0-1) [3](#0-2)

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
