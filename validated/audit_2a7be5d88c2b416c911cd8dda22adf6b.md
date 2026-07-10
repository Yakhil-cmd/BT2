### Title
Zero Echo/Ready Thresholds for n ≤ 3 Allow Commitment Equivocation in DKG, Causing Inconsistent Public Keys — (`src/protocol/echo_broadcast.rs`, `src/dkg.rs`)

---

### Summary

`echo_ready_thresholds` returns `(0, 0)` for any `n ≤ 3`, meaning the echo-broadcast protocol provides **zero cross-validation** for small party sizes. Combined with the fact that the commitment hash in Round 2 is sent via plain `send_many` (no broadcast protection at all), a malicious participant in a 3-party DKG can send different `(commitment, commitment_hash, proof_of_knowledge)` tuples to each honest party. Both honest parties pass all local verification checks and complete the DKG holding **different public keys**.

---

### Finding Description

**Root cause 1 — zero thresholds for n ≤ 3:** [1](#0-0) 

With `echo_t = 0` and `ready_t = 0`, the delivery conditions become:

- Echo phase fires when `count > 0` → triggered by the **simulated self-echo alone** (line 208–209), before any real cross-party echo is received.
- Ready amplification fires when `count > 0` → triggered by the **simulated self-ready alone** (line 289–291).
- Final delivery fires when `count > 2 * 0 = 0` → also triggered by the simulated self-ready. [2](#0-1) [3](#0-2) 

Each honest party therefore delivers whatever value it received in the initial `SEND` message, with no cross-validation from the other honest party. The broadcast provides **no equivocation protection** for n ≤ 3.

**Root cause 2 — commitment hash sent via plain `send_many`:** [4](#0-3) 

The commitment hash `h_i = H(i, C_i, sid)` is sent with an unauthenticated `send_many`, not via `do_broadcast`. There is no mechanism to detect that a malicious party sent different hashes to different recipients.

**The attack (3-party DKG: P1 = malicious, P2 and P3 = honest):**

1. **Round 1 (session-id broadcast):** P1 behaves honestly, sending the same `my_session_id` to both P2 and P3. Both honest parties derive the **same** `session_id`. This keeps `broadcast_success` from aborting later.

2. **Round 2 (commitment hash, plain send):** P1 picks two distinct secrets `s_A` and `s_B`, computes commitments `C_A` and `C_B`, and sends:
   - `h_A = H(P1, C_A, session_id)` to P2
   - `h_B = H(P1, C_B, session_id)` to P3

3. **Round 3 (commitment + proof broadcast via `do_broadcast`):** With `echo_t = ready_t = 0`, P1 sends `(C_A, Proof_A)` to P2 and `(C_B, Proof_B)` to P3. Each honest party delivers immediately from its own simulated echo/ready, with no cross-check.

4. **Round 4 (verification):** Each honest party runs:
   - `verify_proof_of_knowledge(session_id, ..., C_x, Proof_x)` — passes, because P1 crafted each proof for the correct `session_id` and its respective commitment.
   - `verify_commitment_hash(session_id, P1, ..., C_x, {P1: h_x})` — passes, because P1 sent a matching hash for each commitment. [5](#0-4) 

5. **Public key computation:** P2 computes `PK_A = C_A(0) + C_2(0) + C_3(0)` and P3 computes `PK_B = C_B(0) + C_2(0) + C_3(0)`. Since `C_A ≠ C_B`, `PK_A ≠ PK_B`.

6. **`broadcast_success` (Round 5.4):** Both honest parties broadcast the **same** `session_id` (P1 was honest in Round 1), so the session-id agreement check passes silently. [6](#0-5) 

The DKG completes without error. P2 and P3 hold inconsistent public keys and incompatible key shares.

---

### Impact Explanation

**High — Corruption of DKG outputs so honest parties accept inconsistent public keys.**

P2 and P3 each believe the DKG succeeded and hold a `KeygenOutput` with a different `public_key`. Any subsequent signing attempt between P2 and P3 will fail or produce an invalid signature, because their views of the group public key diverge. P1 additionally controls the exact value of its own secret contribution (`s_A` or `s_B`) to each honest party's view, choosing it freely.

---

### Likelihood Explanation

The attack requires only that a malicious participant be present in a 3-party DKG session. The library's `assert_key_invariants` enforces `n ≥ 2` and `2 ≤ threshold ≤ n`, but imposes **no lower bound on n relative to the number of tolerated malicious parties**. [7](#0-6) 

The README states the DKG "can only tolerate n/3 malicious parties," which for n=3 implies tolerance of 1 malicious party. The implementation silently provides zero tolerance for n ≤ 3, with no API-level guard to prevent this misconfiguration. [8](#0-7) 

---

### Recommendation

1. **Remove the `n ≤ 3` special case.** For n=3, the correct thresholds from the CGR formula are `echo_t = midpoint(3, 0) = 1` and `ready_t = 0`. Applying these requires each honest party to collect at least 2 echoes before sending READY, which forces cross-validation between the two honest parties and prevents equivocation.

2. **Protect the commitment hash with `do_broadcast`.** The Round 2 commitment hash (`h_i`) is currently sent via plain `send_many`. It should be sent via `do_broadcast` (or at minimum, the received hashes should be cross-checked via a broadcast round) so that all parties agree on the same set of hashes.

3. **Add an API-level guard** in `assert_key_invariants` that rejects `n ≤ 3` when the caller intends to tolerate any malicious party, or document explicitly that n=3 provides zero Byzantine fault tolerance.

---

### Proof of Concept

Simulate a 3-party DKG where P1 is malicious:

```rust
// P1 behaves honestly in Round 1 (same session_id to all)
// but in Round 3, sends different (commitment, proof) pairs:
//   - (C_A, Proof_A) to P2
//   - (C_B, Proof_B) to P3
// and in Round 2 (plain send_many), sends:
//   - h_A = H(P1, C_A, session_id) to P2
//   - h_B = H(P1, C_B, session_id) to P3
//
// With echo_t = ready_t = 0, P2 and P3 each deliver
// their respective (C_x, Proof_x) without cross-checking.
//
// Assert at the end:
assert_ne!(p2_output.public_key, p3_output.public_key);
// Both outputs are Ok(KeygenOutput { ... }) — no error is raised.
```

The key invariant violated is that `do_broadcast` for n ≤ 3 delivers after only the simulated self-echo/ready, making it equivalent to a plain point-to-point send with no agreement guarantee.

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

**File:** src/protocol/echo_broadcast.rs (L223-235)
```rust
                if state_sid.data_echo.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > echo_t
                {
                    vote = MessageType::Ready(data);
                    chan.send_many(wait, &(&sid, &vote))?;
                    // state that the echo phase for session id (sid) is done
                    state_sid.finish_echo = true;

                    // simulate a ready vote sent by me
                    is_simulated_vote = true;
                    from = me;
                }
```

**File:** src/protocol/echo_broadcast.rs (L280-295)
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
```

**File:** src/dkg.rs (L307-337)
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
```

**File:** src/dkg.rs (L413-426)
```rust
    // Step 2.9
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &commitment_hash)?;
    // receive commitment_hash

    let mut all_hash_commitments = ParticipantMap::new(&participants);
    all_hash_commitments.put(me, commitment_hash);

    // Step 3.1
    for (from, their_commitment_hash) in
        recv_from_others(&chan, wait_round_1, &participants, me).await?
    {
        all_hash_commitments.put(from, their_commitment_hash);
    }
```

**File:** src/dkg.rs (L446-469)
```rust
    for p in participants.others(me) {
        let (commitment_i, proof_i) = commitments_and_proofs_map.index(p)?;

        // verify the proof of knowledge
        // if proof is none then make sure the participant is new
        // and performing a resharing not a DKG
        verify_proof_of_knowledge(
            &session_id,
            &mut proof_domain_separator.clone(), // you want to have the same state
            threshold,
            p,
            old_participants.clone(),
            commitment_i,
            proof_i.as_ref(),
        )?;

        // verify that the commitment sent hashes to the received commitment_hash in round 1
        verify_commitment_hash(
            &session_id,
            p,
            &mut commit_domain_separator.clone(), // you want to have the same state
            commitment_i,
            &all_hash_commitments,
        )?;
```

**File:** src/dkg.rs (L558-596)
```rust
pub fn assert_key_invariants(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<ParticipantList, InitializationError> {
    let threshold = usize::from(threshold.into());
    // need enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // Step 1.1
    // validate threshold
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }

    // ensure uniqueness of participants in the participant list
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
    Ok(participants)
}
```
