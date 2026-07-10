### Title
Single Malicious Participant's Equivocation Permanently Aborts All Concurrent Broadcast Sessions, Blocking DKG/Reshare/Refresh — (`src/protocol/echo_broadcast.rs`)

---

### Summary

`reliable_broadcast_receive_all` runs **n concurrent broadcast instances** simultaneously (one per participant). An early-termination guard at lines 257–263 causes the **entire function** to return an error the moment any single participant's session is detected as unresolvable. A single malicious participant who equivocates in its own `Send` phase can deterministically trigger this guard, permanently aborting DKG, reshare, and refresh for every honest party.

---

### Finding Description

`reliable_broadcast_receive_all` in `src/protocol/echo_broadcast.rs` manages `n` independent echo-broadcast sessions in a single loop. After counting echo votes for a given session `sid`, the function applies an early-termination check:

```rust
// lines 241-263
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
``` [1](#0-0) 

When this `return Err(...)` fires for **any** session `sid`, the function exits immediately — abandoning all other `n-1` sessions that may be progressing normally.

**Attack path:**

A malicious participant M (index `sid = k`) sends different `MessageType::Send` payloads to different subsets of honest parties during its own broadcast turn. Honest parties then echo different values for session `k`. Once all `n` echo votes are collected and no single value has accumulated more than `echo_t` votes, the condition `cnt + 0 > echo_t` fails for every candidate, `is_enough` stays `false`, and the function returns an error — even though all other `n-1` sessions were completing correctly.

The call chain that propagates this abort:

```
reliable_broadcast_receive_all  (echo_broadcast.rs:140)
  └─ do_broadcast               (echo_broadcast.rs:334)
       └─ do_keyshare           (dkg.rs:362, 435, 531)
            ├─ do_keygen        (dkg.rs:540)
            ├─ do_reshare       (dkg.rs:600)
            └─ broadcast_success (dkg.rs:307)
``` [2](#0-1) [3](#0-2) [4](#0-3) 

Every call to `do_broadcast` propagates the error via `?`, so a single equivocating participant causes `do_keyshare` — and therefore every DKG, reshare, and refresh invocation — to return `Err` for all honest parties.

The existing test `test_three_honest_one_dihonest` (lines 547–577) confirms this: with `n = 4` (satisfying `n ≥ 3f+1 = 4` for `f = 1`), a single dishonest participant equivocating in its own `Send` phase causes the protocol to abort with exactly this error. [5](#0-4) 

---

### Impact Explanation

**High — Permanent denial of DKG, reshare, and refresh for honest parties under valid protocol inputs and documented trust assumptions.**

The library's echo-broadcast layer is parameterized to tolerate `f = (n-1)/3` malicious parties. For `n = 4`, `f = 1`; for `n = 7`, `f = 2`. Despite satisfying this threshold, a single malicious participant can abort the entire key-generation or resharing ceremony for all honest parties by equivocating in its own broadcast session. No key material is ever produced; the ceremony must be restarted, and the attacker can repeat the attack indefinitely, achieving permanent denial of key generation, resharing, and refresh.

---

### Likelihood Explanation

**High.** The attack requires only that a participant send different `MessageType::Send` payloads to different subsets of peers — a trivial network-layer manipulation requiring no cryptographic capability. Any participant admitted to the protocol (a malicious coordinator, a compromised signer, or a rogue new joiner in a reshare) can execute this. The attack is deterministic and repeatable with zero cost.

---

### Recommendation

Replace the hard abort with per-session failure isolation:

1. Mark session `sid` as permanently failed (e.g., set all `finish_*` flags and record a `failed` flag) instead of returning from the function.
2. Continue processing messages for all other sessions.
3. Return `Ok` only when all non-failed sessions have completed, and surface the set of failed (malicious) senders to the caller.
4. Let the caller (DKG/reshare) decide whether the number of failed sessions exceeds the tolerated fault bound `f` before aborting the ceremony.

This mirrors the standard Bracha reliable-broadcast guarantee: a malicious sender's session may not deliver, but it must not prevent honest senders' sessions from completing.

---

### Proof of Concept

The library's own test suite demonstrates the issue:

```rust
// src/protocol/echo_broadcast.rs, lines 547-563
#[test]
fn test_three_honest_one_dihonest() {
    let honest_participants = generate_participants(3);   // n=4 total
    let dishonest_participant = Participant::from(3u32); // f=1, satisfies n >= 3f+1
    let honest_votes = vec![true, true, true];

    // version 1: dishonest sends Send(true) to half, Send(false) to other half
    let result = broadcast_dishonest(
        &honest_participants,
        dishonest_participant,
        &honest_votes,
        do_broadcast_dishonest_consume_version_1,
    );
    // The ENTIRE broadcast (all 4 sessions) aborts:
    assert_eq!(result, Err(ProtocolError::AssertionFailed(
        "The original sender in session 3 is malicious! \
         Could not collect enough echo votes to meet the threshold".to_string()
    )));
}
``` [6](#0-5) 

Concretely, with `n = 4` and `echo_t = 2`:

- M sends `Send(true)` to H1, H2 and `Send(false)` to H3.
- H1, H2 echo `true`; H3 echoes `false`; M echoes `false`.
- After all 4 echo votes are tallied for session 3: `true` → 2 votes, `false` → 2 votes.
- `non_received_echo_cnt = 0`; `2 + 0 = 2`, which is **not** `> echo_t = 2`.
- `is_enough = false` → `return Err(...)` aborts all four sessions.

The same mechanism applies inside `do_keyshare` at every `do_broadcast` call site, making DKG, reshare, and refresh permanently deniable by any single admitted participant. [7](#0-6) [8](#0-7)

### Citations

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

**File:** src/protocol/echo_broadcast.rs (L547-577)
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
        // version 2
        let result = broadcast_dishonest(
            &honest_participants,
            dishonest_participant,
            &honest_votes,
            do_broadcast_dishonest_consume_version_2,
        )
        .unwrap();

        for (_, vec_b) in &result {
            let false_count = vec_b.iter().filter(|&&b| !b).count();
            assert_eq!(false_count, 0);
        }
    }
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
