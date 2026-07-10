### Title
Malicious Sender Equivocation in Echo Phase Triggers Asymmetric Early-Abort, Permanently Desynchronizing DKG — (`src/protocol/echo_broadcast.rs`)

---

### Summary

A malicious participant M can permanently abort a subset of honest parties during DKG by equivocating in both the Send and Echo phases of `reliable_broadcast_receive_all`. The early-abort check at line 241–263 fires based purely on local echo-vote state, with no cross-party consistency guarantee. M can engineer a message distribution where the check fires for exactly one honest party (returning `Err(AssertionFailed)`) while the remaining honest parties proceed normally, permanently desynchronizing the DKG.

---

### Finding Description

**Threshold computation for n=4:** [1](#0-0) 

```
broadcast_threshold = (4-1)/3 = 1
echo_threshold      = usize::midpoint(4, 1) = 2
```

So `echo_t = 2`. The threshold check requires `count > echo_t`, i.e., `count >= 3`.

**The early-abort check** fires in the Echo handler when the threshold branch is not taken: [2](#0-1) 

It aborts when, for every observed value `v`: `cnt(v) + non_received_echo_cnt <= echo_t`. This is a purely local check — it has no knowledge of what other honest parties have observed.

**The Send handler has no equivocation protection:** [3](#0-2) 

M can send `Send(A)` to H1 and `Send(B)` to H2, H3 with no detection.

**The Echo handler also has no equivocation protection:** [4](#0-3) 

`seen_echo.put(from)` only prevents duplicate echoes from the same sender per session; it does not prevent M from sending `Echo(A)` to H1 and `Echo(B)` to H2/H3.

---

### Concrete Attack (n=4, echo_t=2, ready_t=1)

Participants: M (malicious), H1, H2, H3 (honest).

**Send phase (M's session):**
- M → H1: `Send(A)`
- M → H2, H3: `Send(B)`

**Echo phase (honest parties echo what they received):**
- H1 → all: `Echo(A)`
- H2 → all: `Echo(B)`
- H3 → all: `Echo(B)`
- M → H1: `Echo(A)` (equivocating)
- M → H2, H3: `Echo(B)`

**H1's final echo state for M's session:**

| Value | Count | non_received | cnt + non_received |
|-------|-------|-------------|-------------------|
| A     | 2     | 0           | 2 (NOT > 2)       |
| B     | 2     | 0           | 2 (NOT > 2)       |

`is_enough = false` → **H1 returns `Err(AssertionFailed("...malicious..."))`** — permanently aborted.

**H2's and H3's final echo state for M's session:**

| Value | Count | non_received | cnt + non_received |
|-------|-------|-------------|-------------------|
| A     | 1     | 0           | 1 (NOT > 2)       |
| B     | 3     | 0           | 3 (> 2 ✓)         |

`is_enough = true` → H2 and H3 proceed to `Ready(B)` — **no abort**.

H1 is permanently dead while H2/H3 continue. The DKG is irrecoverably desynchronized.

---

### Impact Explanation

H1 returns a hard `Err` from `reliable_broadcast_receive_all`, which propagates through `do_broadcast` and terminates H1's participation in DKG/reshare/refresh permanently. [5](#0-4) [6](#0-5) 

This matches the **High** impact: *Permanent denial of key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions.*

---

### Likelihood Explanation

The attack requires only one Byzantine participant who can send different messages to different parties — the standard Byzantine adversary model this protocol is designed to tolerate. No cryptographic assumptions need to be broken. The exact message distribution is computable analytically for any `n >= 4`. The attack is deterministic and requires no timing or side-channel access.

---

### Recommendation

The early-abort check must not fire for an honest party when the echo split is itself caused by sender equivocation. Two complementary fixes:

1. **Remove or gate the early-abort check**: Only fire it after `finish_amplification` is set (i.e., after the Ready amplification phase confirms the sender's equivocation is unresolvable). The `!state_sid.finish_amplification` guard currently does the opposite — it fires the check *only before* amplification, which is exactly when the split is still ambiguous.

2. **Add equivocation detection in the Send phase**: Track the first `Send` value received for each session and reject subsequent `Send` messages with a different value from the same sender, preventing the echo split from occurring in the first place.

---

### Proof of Concept

The existing test `test_three_honest_one_dihonest` in `src/protocol/echo_broadcast.rs` (line 548) already demonstrates the pattern with n=4. Extending `do_broadcast_dishonest_consume_version_1` to also send `Echo(A)` to H1 in M's own session (after the Send phase) would reproduce the asymmetric abort: H1 returns `Err(AssertionFailed)` while H2 and H3 complete successfully. [7](#0-6)

### Citations

**File:** src/protocol/echo_broadcast.rs (L75-77)
```rust
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
```

**File:** src/protocol/echo_broadcast.rs (L193-205)
```rust
            MessageType::Send(data) => {
                // If the sender is not the one identified by the session id (sid)
                // or if the sender have already delivered a MessageType::Send message
                // then skip.
                // The second condition prevents a malicious party starting the protocol
                // on behalf on somebody else
                if state_sid.finish_send || sid != participants.index(from)? {
                    continue;
                }
                vote = MessageType::Echo(data);
                // upon receiving a send message, echo it
                chan.send_many(wait, &(&sid, &vote))?;
                state_sid.finish_send = true;
```

**File:** src/protocol/echo_broadcast.rs (L212-219)
```rust
            MessageType::Echo(data) => {
                // skip if I received echo message from the sender in a specific session (sid)
                // or if I had already passed to the ready phase in this same session
                if !state_sid.seen_echo.put(from) || state_sid.finish_echo {
                    continue;
                }
                // insert or increment the number of collected echo of a specific vote
                state_sid.data_echo.insert_or_increase_counter(data.clone());
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

**File:** src/protocol/echo_broadcast.rs (L334-347)
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
```

**File:** src/protocol/echo_broadcast.rs (L412-437)
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
    }
```
