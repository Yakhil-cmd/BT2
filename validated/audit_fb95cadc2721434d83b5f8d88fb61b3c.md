### Title
Single Malicious Participant Triggers Whole-Function Early-Abort in Echo Broadcast, Permanently Denying DKG/Reshare for All Honest Parties — (File: `src/protocol/echo_broadcast.rs`)

---

### Summary

The `reliable_broadcast_receive_all` function contains an early-abort optimization that calls `return Err(...)` — terminating the **entire** function and all N concurrent broadcast sessions — the moment it determines that one session's sender is malicious. A single malicious participant can deliberately equivocate (send conflicting `MessageType::Send` values to different peers) in their own session to trigger this abort, causing every honest participant to fail the DKG, reshare, or presign protocol. This is directly analogous to the external report's pattern: a shared state variable (the echo-vote counter) is manipulated to hit a limit (the echo threshold), blocking all honest parties from completing their operation.

---

### Finding Description

`reliable_broadcast_receive_all` in `src/protocol/echo_broadcast.rs` runs N simultaneous echo-broadcast sessions (one per participant). For each session `sid`, it tracks received ECHO votes in `data_echo` (a `CounterList`) and enforces per-participant deduplication via `seen_echo` (a `ParticipantCounter`).

After counting each incoming ECHO, if the threshold has not yet been reached, the function executes an early-abort check: [1](#0-0) 

```rust
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

The `return Err(...)` exits the **entire** `reliable_broadcast_receive_all` call, not just the failing session. All other sessions — including those belonging to honest participants — are abandoned.

A malicious participant (the sender for their own session `sid`) can deliberately split echo votes by sending different `MessageType::Send` payloads to different peers: [2](#0-1) 

This causes honest peers to echo different values for that session. Once all echoes are received, no single value accumulates enough votes to exceed `echo_t`, `non_received_echo_cnt` drops to zero, and the check fires — aborting the entire function.

The `do_broadcast` wrapper that calls this function is imported and used directly in `src/dkg.rs`: [3](#0-2) 

So the abort propagates up through `do_keyshare` → `do_keygen` / `do_reshare`, killing the DKG or reshare protocol for every honest participant.

---

### Impact Explanation

**High — Permanent denial of key generation and reshare for honest parties under valid protocol inputs and documented trust assumptions.**

The BFT assumption documented for the echo broadcast is `n > 3 · MaxFaulty`: [4](#0-3) 

With `n = 4` and `f = 1` (satisfying `4 > 3`), a single malicious participant can abort the entire DKG for all three honest participants. Because the malicious participant can repeat this on every retry, the denial is effectively permanent. The honest parties cannot complete key generation or resharing as long as the malicious participant is present.

---

### Likelihood Explanation

**High.** The attack requires no special resources: the malicious participant simply sends different `MessageType::Send` payloads to different peers in their own session. No cryptographic capability, no leaked key, no external dependency. The existing test `test_three_honest_one_dihonest` in `src/protocol/echo_broadcast.rs` already demonstrates and confirms this exact failure mode with `n = 4`: [5](#0-4) 

The test asserts the protocol returns `Err(ProtocolError::AssertionFailed("The original sender in session 3 is malicious! ..."))` — confirming that honest participants are aborted by a single equivocating peer within the documented trust bound.

---

### Recommendation

Replace the `return Err(...)` in the early-abort path with a per-session failure marker. When a session is detected as having a malicious sender, mark only that session's state as permanently failed (e.g., set all `finish_*` flags to `true` and record a sentinel error for that slot) and continue the loop to process remaining sessions. The function should only propagate a fatal error if the number of failed sessions exceeds the protocol's tolerance, or if the caller's own session fails. This mirrors the correct behavior of the standard echo-broadcast protocol, which guarantees progress for honest senders even when some senders are malicious.

---

### Proof of Concept

1. Instantiate a DKG with `n = 4` participants (`P0`, `P1`, `P2` honest; `P3` malicious), `threshold = 2`. This satisfies `n > 3f` (`4 > 3`).
2. `P3` (the sender for session `sid = 3`) sends `MessageType::Send(true)` privately to `P0` and `P1`, and `MessageType::Send(false)` privately to `P2`.
3. `P0` and `P1` echo `true`; `P2` echoes `false`; `P3` simulates an echo of `false`.
4. For session 3: `cnt_true = 2`, `cnt_false = 2`, `non_received_echo_cnt = 0`. With `echo_t = 2` (computed as `midpoint(4, 1) = 2`), neither `2 + 0 > 2` nor `2 + 0 > 2` holds.
5. `is_enough = false` → `return Err(ProtocolError::AssertionFailed(...))` fires inside every honest participant's `reliable_broadcast_receive_all` call.
6. `do_broadcast` → `do_keyshare` → `do_keygen` all return the error. The DKG fails for all honest parties. [6](#0-5) [7](#0-6)

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

**File:** src/protocol/echo_broadcast.rs (L140-155)
```rust
pub async fn reliable_broadcast_receive_all<'a, T>(
    chan: &SharedChannel,
    wait: Waitpoint,
    participants: &'a ParticipantList,
    me: Participant,
    send_vote: MessageType<T>,
) -> Result<ParticipantMap<'a, T>, ProtocolError>
where
    T: Serialize + Clone + DeserializeOwned + PartialEq,
{
    let n = participants.len();
    let (echo_t, ready_t) = echo_ready_thresholds(n);

    let mut vote_output = ParticipantMap::new(participants);

    let mut state = vec![BroadcastProtocolState::new(participants); n];
```

**File:** src/protocol/echo_broadcast.rs (L241-263)
```rust
                else if !state_sid.finish_amplification {
                    // calculate the total number of echos already collected
                    let received_echo_cnt = state_sid.data_echo.get_sum_counters();
                    // calculate the number of echo to be received
                    let non_received_echo_cnt = n - received_echo_cnt;
                    // iterate over the state_sid.data_echo array
                    let mut is_enough = false;
                    for (_, cnt) in state_sid.data_echo.iter() {
                        // verify whether there is enough votes in at
                        // least one slot to exceed the threshold
                        if cnt + non_received_echo_cnt > echo_t {
                            is_enough = true;
                            break;
                        }
                    }

                    // if not enough echo votes left for hitting the threshold
                    // then we know that the sender is malicious
                    if !is_enough {
                        return Err(ProtocolError::AssertionFailed(format!(
                            "The original sender in session {sid:?} is malicious! Could not collect enough echo votes to meet the threshold"
                        )));
                    }
```

**File:** src/protocol/echo_broadcast.rs (L412-436)
```rust
    async fn do_broadcast_dishonest_consume_version_1(
        mut chan: SharedChannel,
        participants: ParticipantList,
        me: Participant,
    ) -> Result<Vec<bool>, ProtocolError> {
        let wait_broadcast = chan.next_waitpoint();
        let sid = participants.index(me)?;

        // malicious reliable broadcast send
        let vote_true = MessageType::Send(true);
        let vote_false = MessageType::Send(false);

        for (cnt, p) in participants.others(me).enumerate() {
            if cnt >= participants.len() / 2 {
                chan.send_private(wait_broadcast, p, &(&sid, &vote_false))?;
            } else {
                chan.send_private(wait_broadcast, p, &(&sid, &vote_true))?;
            }
        }

        let vote_list =
            reliable_broadcast_receive_all(&chan, wait_broadcast, &participants, me, vote_false)
                .await?;
        let vote_list = vote_list.into_vec_or_none().unwrap();
        Ok(vote_list)
```

**File:** src/protocol/echo_broadcast.rs (L547-563)
```rust
    #[test]
    fn test_three_honest_one_dihonest() {
        // threshold is assumed to be n >= 3*threshold + 1
        let honest_participants = generate_participants(3);

        let dishonest_participant = Participant::from(3u32);

        let honest_votes = vec![true, true, true];

        // version 1
        let result = broadcast_dishonest(
            &honest_participants,
            dishonest_participant,
            &honest_votes,
            do_broadcast_dishonest_consume_version_1,
        );
        assert_eq!(result, Err(ProtocolError::AssertionFailed("The original sender in session 3 is malicious! Could not collect enough echo votes to meet the threshold".to_string())));
```

**File:** src/dkg.rs (L9-11)
```rust
use crate::protocol::{
    echo_broadcast::do_broadcast, helpers::recv_from_others, internal::SharedChannel,
};
```

**File:** docs/network-layer.md (L39-39)
```markdown
> To guarantee the security notions given by the Byzantine Reliable Broadcast, we assume that $3 \cdot \mathsf{MaxFaulty} +1 \leq N$. This bound originates from the classical Byzantine fault tolerance model \[[LSP82](https://lamport.azurewebsites.net/pubs/byz.pdf)\], which ensures both safety and liveness under such faults.
```
