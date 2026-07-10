### Title
Reliable Broadcast Agreement Failure at n=3 Enables Equivocation in DKG — (`src/protocol/echo_broadcast.rs`)

---

### Summary

`echo_ready_thresholds(3)` returns `(0, 0)`, causing the delivery condition `count > 2 * ready_t` to reduce to `count > 0`. A malicious participant can send different commitment values to different honest parties in the SEND phase. Each honest party immediately delivers its own received value after a single self-simulated echo/ready chain, with no cross-party agreement check. In a 3-party DKG, this causes honest parties to compute different `verifying_key` values.

---

### Finding Description

**Root cause — `echo_ready_thresholds`:** [1](#0-0) 

For `n <= 3`, both `echo_t` and `ready_t` are `0`. This is documented as "no malicious parties assumed," but the function is called unconditionally regardless of whether a malicious party is actually present.

**Delivery condition with `ready_t = 0`:** [2](#0-1) 

`2 * ready_t = 0`, so `count > 0` is satisfied by the very first Ready message — which is always the participant's own simulated self-ready, generated immediately after receiving the SEND message.

**Self-simulation chain that triggers instant delivery:**

When honest party B receives `Send(X)` from attacker A:
1. B echoes `Echo(X)` and simulates its own echo → `count_echo[X] = 1 > 0` → sends `Ready(X)`, `finish_echo = true`
2. B simulates its own ready → `count_ready[X] = 1 > 0` → amplifies (line 280–287) AND immediately delivers X (line 293–307) in the same iteration, since both `if` blocks are independent (not `else if`) [3](#0-2) 

Party C, having received `Send(Y)`, follows the identical path and delivers Y. No external message from the other honest party is ever awaited before delivery.

**DKG impact — commitment broadcast in Round 3:** [4](#0-3) 

The attacker broadcasts `(commitment_X, proof_X)` to B and `(commitment_Y, proof_Y)` to C. The hash-commitment check in Round 4 (line 463) does not prevent this because the Round 2 hash is sent via plain `send_many` (line 415), allowing the attacker to also send different hashes tailored to each commitment: [5](#0-4) 

Both B and C pass `verify_commitment_hash` with their respective (hash, commitment) pairs. They then compute different aggregate public keys: [6](#0-5) 

**Existing tests do not cover this case.** `test_three_honest_one_dihonest` uses 4 total participants (3 honest + 1 dishonest), where `echo_ready_thresholds(4)` returns non-zero thresholds and the protocol is protected: [7](#0-6) 

---

### Impact Explanation

Honest parties B and C complete DKG with different `verifying_key` values. Any signature produced by B's share is unverifiable by C and vice versa. The group key is split, making the threshold signing scheme permanently unusable for the affected key material. This matches: **High — Corruption of DKG outputs so honest parties accept inconsistent public keys.**

---

### Likelihood Explanation

- Minimum viable attack requires exactly n=3 participants, one of whom is malicious — the documented minimum for DKG.
- The attacker uses the standard protocol API (`send_private` per-recipient in the SEND phase), requiring no cryptographic breaks.
- No external assumptions beyond participant-level Byzantine behavior are needed.
- The `(0, 0)` threshold path is unconditional code, not a configuration option.

---

### Recommendation

The `n <= 3` special case in `echo_ready_thresholds` must be removed or replaced. The correct thresholds for n=3 with `MaxFaulty = floor((3-1)/3) = 0` are `echo_t = floor((3+0)/2) = 1` and `ready_t = 0`, but since `MaxFaulty = 0` for n=3, the protocol should either:

1. **Reject n=3 with any malicious party** — enforce `n >= 4` as the minimum for DKG when Byzantine fault tolerance is required, or
2. **Use correct thresholds for n=3** — `echo_t = n - 1 = 2` (require all echoes), `ready_t = 0`, delivery threshold `> 0` (i.e., 1 ready suffices only after seeing all echoes). This degenerates to a simple all-echo-required protocol with no fault tolerance, which is correct for `MaxFaulty = 0`.

The two independent `if` blocks for amplification and delivery (lines 280–295) should also be restructured so delivery cannot occur in the same iteration as the first self-simulated ready, preventing the zero-external-message delivery path.

---

### Proof of Concept

```
Participants: A (malicious sender), B (honest), C (honest), n=3
echo_t = 0, ready_t = 0

A → B: Send(commitment_X)   // different value
A → C: Send(commitment_Y)   // different value

B: Echo(X) → all; simulated Echo(X) → count_echo[X]=1 > 0 → Ready(X)
   simulated Ready(X) → count_ready[X]=1 > 0 → amplify + deliver X  ← no external msg needed

C: Echo(Y) → all; simulated Echo(Y) → count_echo[Y]=1 > 0 → Ready(Y)
   simulated Ready(Y) → count_ready[Y]=1 > 0 → amplify + deliver Y  ← no external msg needed

B.verifying_key = C_B(0) + C_C(0) + commitment_X(0)
C.verifying_key = C_B(0) + C_C(0) + commitment_Y(0)
→ B.verifying_key ≠ C.verifying_key  // split-view on group public key
```

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

**File:** src/protocol/echo_broadcast.rs (L280-307)
```rust
                if state_sid.data_ready.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > ready_t
                    && !state_sid.finish_amplification
                {
                    vote = MessageType::Ready(data.clone());
                    chan.send_many(wait, &(&sid, &vote))?;
                    state_sid.finish_amplification = true;

                    // simulate a ready vote sent by me
                    is_simulated_vote = true;
                    from = me;
                }
                if state_sid.data_ready.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > 2 * ready_t
                {
                    // skip all types of messages sent for session sid from now on
                    state_sid.finish_send = true;
                    state_sid.finish_echo = true;
                    state_sid.finish_ready = true;

                    // return a map of participant data
                    let p = participants
                        .get_participant(sid)
                        .ok_or_else(|| ProtocolError::Other("Missing participant".to_string()))?;
                    // make a list of data and return them
                    vote_output.put(p, data.clone());
```

**File:** src/protocol/echo_broadcast.rs (L548-563)
```rust
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

**File:** src/dkg.rs (L414-415)
```rust
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &commitment_hash)?;
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

**File:** src/dkg.rs (L484-485)
```rust
    // Step 4.5
    let verifying_key = public_key_from_commitments(all_commitments_refs)?;
```
