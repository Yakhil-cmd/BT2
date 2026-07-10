### Title
Single Malicious Participant Can Permanently Abort DKG, Reshare, and Refresh via `broadcast_success` Unanimous-Vote Requirement - (File: `src/dkg.rs`)

---

### Summary

The `broadcast_success` function in `src/dkg.rs` is called at the very end of `do_keyshare` (which backs DKG, reshare, and refresh). It requires **all** participants to broadcast `(true, session_id)` — a unanimous vote. A single malicious participant within the BFT tolerance can broadcast `(false, session_id)` or `(true, wrong_session_id)`, causing every honest party to abort the protocol after completing all prior expensive rounds.

---

### Finding Description

`broadcast_success` is the final step of `do_keyshare`:

```rust
// src/dkg.rs:307-338
async fn broadcast_success(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    session_id: HashOutput,
) -> Result<(), ProtocolError> {
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
    let vote_list = vote_list
        .into_vec_or_none()
        .ok_or_else(|| ProtocolError::AssertionFailed("vote_list is empty".to_string()))?;

    if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
        return Err(ProtocolError::AssertionFailed(
            "A participant broadcast the wrong session id. Aborting Protocol!".to_string(),
        ));
    }

    if !vote_list.iter().all(|&(boolean, _)| boolean) {
        return Err(ProtocolError::AssertionFailed(
            "A participant seems to have failed its checks. Aborting Protocol!".to_string(),
        ));
    }
    Ok(())
}
``` [1](#0-0) 

It is invoked unconditionally at the end of `do_keyshare`:

```rust
// src/dkg.rs:530-531
broadcast_success(&mut chan, &participants, me, session_id).await?;
``` [2](#0-1) 

The underlying `do_broadcast` uses the Echo Broadcast protocol, which is BFT-tolerant up to `MaxFaulty = (N-1)/3` faulty participants. The echo broadcast **will complete** even with up to `MaxFaulty` malicious participants — it guarantees all honest parties receive the same message from each sender. However, after the broadcast completes, `broadcast_success` applies `.all(...)` — a **unanimous** check — over the collected votes. This check is not BFT-tolerant: a single malicious participant broadcasting `(false, session_id)` is faithfully delivered to all honest parties by the echo broadcast, and then the `.all()` check fails for every honest party.

The attack path:

1. Malicious participant `P_m` joins a DKG/reshare/refresh session with `N >= 4` participants (so `MaxFaulty >= 1`).
2. `P_m` participates honestly through all five rounds of `do_keyshare` (session-id broadcast, commitment hash, commitment+proof broadcast, secret share distribution, share validation).
3. In the final `broadcast_success` call, `P_m` calls `do_broadcast` with `(false, session_id)` instead of `(true, session_id)`.
4. The echo broadcast protocol delivers `P_m`'s `false` vote to all honest parties (this is the protocol's correctness guarantee).
5. Every honest party evaluates `vote_list.iter().all(|&(boolean, _)| boolean)` → `false` → returns `ProtocolError::AssertionFailed`.
6. All honest parties abort. The DKG/reshare/refresh is permanently denied.

The same effect is achieved by broadcasting `(true, wrong_session_id)`, which triggers the first `.all()` check. [3](#0-2) 

---

### Impact Explanation

This permanently denies key generation, resharing, and refresh for all honest parties. After aborting, the honest parties hold no usable output — they must restart the entire protocol from scratch. A malicious participant can repeat this attack on every subsequent attempt, indefinitely blocking the group from ever completing DKG or key management operations.

This matches the allowed impact: **High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

Any participant in a DKG/reshare/refresh session can execute this attack. The attacker need only be one of the `N` participants — no special privilege is required. The BFT model explicitly documents tolerance of up to `MaxFaulty` faulty participants, so a single malicious participant within that bound is a realistic and expected threat model. The attack requires no cryptographic break, no leaked keys, and no external dependency — only the ability to send a message with `boolean = false`. [4](#0-3) 

---

### Recommendation

Replace the unanimous `.all()` check with a threshold-tolerant check. Specifically, require that at least `N - MaxFaulty` participants broadcast `(true, session_id)`, rather than requiring all `N`. This aligns the success-broadcast check with the BFT tolerance already used throughout the rest of the protocol. The `echo_ready_thresholds` helper already computes the correct BFT threshold from `N`:

```rust
// src/protocol/echo_broadcast.rs:67-78
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    if n <= 3 {
        return (0, 0);
    }
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
}
``` [5](#0-4) 

`broadcast_success` should count how many participants voted `(true, session_id)` and require that count to exceed `N - MaxFaulty`, rather than requiring unanimity.

---

### Proof of Concept

**Setup:** 4 participants `[P0, P1, P2, P3]`, threshold = 2, `MaxFaulty = 1`. `P3` is malicious.

**Execution:**
- Rounds 1–5 of `do_keyshare`: `P3` participates honestly (sends correct session-id, commitment, proof, and secret share).
- Round 6 (`broadcast_success`): `P3` calls `do_broadcast` with `(false, session_id)`.
- Echo broadcast completes: all of `P0`, `P1`, `P2` receive `P3`'s vote as `(false, session_id)`.
- Each of `P0`, `P1`, `P2` evaluates `vote_list.iter().all(|&(boolean, _)| boolean)` → `false`.
- All three honest parties return `ProtocolError::AssertionFailed("A participant seems to have failed its checks. Aborting Protocol!")`.
- DKG is permanently aborted. No key shares are produced. [6](#0-5) [2](#0-1)

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

**File:** src/dkg.rs (L530-531)
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
