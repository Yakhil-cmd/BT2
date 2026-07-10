### Title
Single Malicious Participant Can Permanently DOS DKG, Reshare, and Refresh via Echo Broadcast Early-Abort - (`File: src/protocol/echo_broadcast.rs`)

### Summary

The multi-sender echo broadcast implementation in `reliable_broadcast_receive_all` contains an early-abort optimization that terminates the **entire** N-session broadcast when it detects that a single sender's session cannot reach the echo threshold. Because `do_broadcast` is called unconditionally in `do_keyshare` (which backs DKG, reshare, and refresh), a single malicious participant can permanently abort key generation for all honest parties by equivocating — even when the number of malicious parties is within the documented Byzantine fault tolerance bound (`3 * MaxFaulty + 1 ≤ N`).

---

### Finding Description

`reliable_broadcast_receive_all` in `src/protocol/echo_broadcast.rs` runs N parallel echo-broadcast sessions simultaneously (one per participant). When processing an echo vote for session `sid`, the function checks whether the echo threshold can still be reached:

```rust
// src/protocol/echo_broadcast.rs lines 241-263
else if !state_sid.finish_amplification {
    let received_echo_cnt = state_sid.data_echo.get_sum_counters();
    let non_received_echo_cnt = n - received_echo_cnt;
    let mut is_enough = false;
    for (_, cnt) in state_sid.data_echo.iter() {
        if cnt + non_received_echo_cnt > echo_t {
            is_enough = true;
            break;
        }
    }
    if !is_enough {
        return Err(ProtocolError::AssertionFailed(format!(
            "The original sender in session {sid:?} is malicious! ..."
        )));
    }
}
```

The `return Err(...)` at line 260 exits the **entire** function — aborting all N sessions, not just the offending one. This is called from `do_broadcast`:

```rust
// src/protocol/echo_broadcast.rs lines 334-348
pub async fn do_broadcast<'a, T>(...) -> Result<ParticipantMap<'a, T>, ProtocolError> {
    let wait_broadcast = chan.next_waitpoint();
    let send_vote = reliable_broadcast_send(...)?;
    let vote_list =
        reliable_broadcast_receive_all(...).await?;
    Ok(vote_list)
}
```

`do_broadcast` is called three times inside `do_keyshare` (the shared core of DKG, reshare, and refresh):

```rust
// src/dkg.rs line 362
let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;
// src/dkg.rs line 435
let commitments_and_proofs_map = do_broadcast(&mut chan, &participants, me, (commitment, proof_of_knowledge)).await?;
// src/dkg.rs line 531 (via broadcast_success)
let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
```

Each `?` propagates the error, aborting the entire DKG/reshare/refresh for all honest participants.

**Attack scenario (N=4, MaxFaulty=1, within documented tolerance):**

With `echo_ready_thresholds(4)` returning `echo_t=2`:

1. Malicious participant P3 sends value `A` to P0 and P1, and value `B` to P2 (equivocation).
2. P0 echoes `A`, P1 echoes `A`, P2 echoes `B`. P3's own simulated echo is `B`.
3. After all 4 echoes are counted for session `sid=3`: `A` has 2 votes, `B` has 2 votes.
4. `non_received_echo_cnt = 0`. For `A`: `2 + 0 = 2`, not `> echo_t=2`. For `B`: same. `is_enough = false`.
5. `return Err(...)` fires — the entire multi-broadcast aborts, taking down all honest participants' DKG sessions.

This is confirmed by the existing test:

```rust
// src/protocol/echo_broadcast.rs lines 557-563
let result = broadcast_dishonest(..., do_broadcast_dishonest_consume_version_1);
assert_eq!(result, Err(ProtocolError::AssertionFailed(
    "The original sender in session 3 is malicious! Could not collect enough echo votes to meet the threshold"
    .to_string())));
```

The test acknowledges the abort but does not test that honest participants' sessions survive.

---

### Impact Explanation

A single malicious participant (within the documented `3 * MaxFaulty + 1 ≤ N` fault tolerance) can permanently prevent all honest parties from completing DKG, reshare, or refresh. The malicious party can repeat the equivocation on every retry, making the denial permanent. This matches the **High** impact category: *Permanent denial of key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions.*

---

### Likelihood Explanation

Any participant in the protocol can trivially equivocate by sending different values to different peers during the echo broadcast SEND phase. No special capability is required beyond being a registered participant. The attack is deterministic and repeatable with zero cryptographic cost.

---

### Recommendation

Scope the early-abort error to the individual session `sid` rather than the entire multi-broadcast. Instead of `return Err(...)`, mark session `sid` as permanently failed (e.g., set a `failed` flag in `BroadcastProtocolState`) and continue processing remaining sessions. The DKG layer can then decide how to handle a failed participant's session (e.g., exclude them and abort with a specific `MaliciousParticipant` error that identifies the culprit), rather than silently aborting all N sessions from within the broadcast primitive.

---

### Proof of Concept

**Entry path:**

1. Attacker is a registered participant in a DKG/reshare/refresh session.
2. During the echo broadcast SEND phase (Round 1 of `do_broadcast`), attacker sends value `A` to `⌊N/2⌋` participants and value `B` to the remaining `⌈N/2⌉` participants.
3. Honest participants echo what they received; the resulting echo vote distribution for the attacker's session is split such that no value can exceed `echo_t`.
4. When any honest participant processes the last echo vote for the attacker's session, `is_enough` evaluates to `false`.
5. `return Err(ProtocolError::AssertionFailed(...))` at [1](#0-0)  exits `reliable_broadcast_receive_all`, propagating through `do_broadcast` at [2](#0-1)  and through all three `do_broadcast` call sites in `do_keyshare` at [3](#0-2) , [4](#0-3) , and [5](#0-4) , aborting DKG/reshare/refresh for all honest parties.

The `echo_ready_thresholds` function confirms that with N=4, `echo_t=2`, making a 2/2 split sufficient to trigger the abort: [6](#0-5)

### Citations

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

**File:** src/protocol/echo_broadcast.rs (L259-263)
```rust
                    if !is_enough {
                        return Err(ProtocolError::AssertionFailed(format!(
                            "The original sender in session {sid:?} is malicious! Could not collect enough echo votes to meet the threshold"
                        )));
                    }
```

**File:** src/protocol/echo_broadcast.rs (L344-346)
```rust
    let send_vote = reliable_broadcast_send(chan, wait_broadcast, participants, me, data)?;
    let vote_list =
        reliable_broadcast_receive_all(chan, wait_broadcast, participants, me, send_vote).await?;
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

**File:** src/dkg.rs (L531-531)
```rust
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```
