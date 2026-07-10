### Title
Single Malicious Participant Permanently Aborts DKG/Reshare/Refresh via False Success Broadcast — (File: `src/dkg.rs`)

---

### Summary

The `broadcast_success` function in `src/dkg.rs` requires **unanimous** agreement from all participants in the final round of `do_keyshare`. A single malicious participant can broadcast `(false, session_id)` — deviating from the honest protocol — to force all honest parties to abort DKG, reshare, or refresh, even after every cryptographic check has already passed successfully.

---

### Finding Description

`do_keyshare` is the shared core of `do_keygen`, `do_reshare`, and `do_refresh`. Its final step calls `broadcast_success`: [1](#0-0) 

```rust
async fn broadcast_success(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    session_id: HashOutput,
) -> Result<(), ProtocolError> {
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
    ...
    if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
        return Err(ProtocolError::AssertionFailed("A participant broadcast the wrong session id..."));
    }
    if !vote_list.iter().all(|&(boolean, _)| boolean) {
        return Err(ProtocolError::AssertionFailed("A participant seems to have failed its checks..."));
    }
    Ok(())
}
``` [2](#0-1) 

The check at lines 321–334 requires **every** participant's broadcast to be `(true, session_id)`. A malicious participant who deviates from the honest implementation and instead calls `do_broadcast` with `(false, session_id)` will cause every honest party to hit the `all(|&(boolean, _)| boolean)` check and return `ProtocolError::AssertionFailed`.

The rest of the DKG uses `do_broadcast` (echo broadcast) which is explicitly designed to tolerate up to `(n−1)/3` Byzantine participants: [3](#0-2) 

```rust
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    if n <= 3 { return (0, 0); }
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
}
```

The echo broadcast layer guarantees that all honest parties receive the **same** value from each sender. So when a malicious participant broadcasts `(false, session_id)`, every honest party consistently receives it and consistently aborts. The Byzantine-fault-tolerant broadcast layer is used correctly, but the unanimity requirement in `broadcast_success` nullifies the fault-tolerance guarantee for the overall DKG outcome.

The attack is structurally identical to the external report: a party who is legitimately part of the session performs a single protocol-level action (broadcasting a false vote instead of registering a derivative) that permanently locks out all honest participants from completing their operation.

---

### Impact Explanation

This is a **permanent denial of key generation, reshare, and refresh** for all honest parties. After `broadcast_success` returns an error, the `do_keyshare` future terminates with `ProtocolError::AssertionFailed`. No output `KeygenOutput` is produced. Honest parties hold no usable key material. Because the malicious participant remains in the participant list, they can repeat the attack on every subsequent retry, making the denial permanent under valid protocol inputs.

Matches: **High — Permanent denial of key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

Any single participant in the protocol can trigger this. No cryptographic capability is required — the attacker only needs to substitute `(false, session_id)` for `(true, session_id)` in the final broadcast round. The attack succeeds even if the malicious participant contributed fully valid polynomial commitments, proofs of knowledge, and secret shares in all prior rounds. The attacker incurs no cost and faces no detection mechanism that would prevent repeated triggering.

---

### Recommendation

Replace the unanimity requirement in `broadcast_success` with a threshold-based check consistent with the Byzantine fault tolerance already provided by the echo broadcast layer. Specifically, the protocol should succeed if at least `threshold` (or `n − f`) participants broadcast `(true, session_id)`, rather than requiring all `n`. Participants who broadcast `false` or a wrong session ID should be identified and excluded from the output participant set, allowing honest parties to complete key generation with the remaining valid contributors.

---

### Proof of Concept

**Setup:** 4 participants — Alice (P1), Bob (P2), Carol (P3), and Mallory (P4, malicious). Threshold = 2.

1. All four participants enter `do_keyshare`.
2. Rounds 1–4 complete honestly: Mallory generates a valid polynomial, broadcasts a valid commitment and proof of knowledge, and sends valid secret shares to P1–P3.
3. All cryptographic checks pass for all honest parties.
4. `broadcast_success` is reached. Honest parties call `do_broadcast(chan, participants, me, (true, session_id))`.
5. Mallory deviates: instead of broadcasting `(true, session_id)`, she calls `do_broadcast(chan, participants, me, (false, session_id))`.
6. The echo broadcast protocol ensures all honest parties consistently receive `(false, session_id)` from Mallory. [4](#0-3) 

7. Each honest party evaluates `vote_list.iter().all(|&(boolean, _)| boolean)` → `false` (Mallory's entry is `false`).
8. Each honest party returns `Err(ProtocolError::AssertionFailed("A participant seems to have failed its checks. Aborting Protocol!"))`.
9. No `KeygenOutput` is produced. Mallory repeats on every retry. DKG is permanently denied.

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
