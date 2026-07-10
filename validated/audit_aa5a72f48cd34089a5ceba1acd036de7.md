### Title
Zero-Threshold Echo-Broadcast Enables Commitment Equivocation in 3-Party DKG, Producing Inconsistent Public Keys — (File: `src/protocol/echo_broadcast.rs`, `src/dkg.rs`)

---

### Summary

The `echo_ready_thresholds` function unconditionally returns `(0, 0)` for any participant set of size ≤ 3. This means the echo-broadcast protocol used throughout DKG provides **zero Byzantine fault tolerance** for the minimum valid participant count. A single malicious participant in a 3-party DKG can exploit this to equivocate on its polynomial commitment — sending a different commitment to each honest participant — causing them to derive inconsistent public keys while the protocol reports success.

---

### Finding Description

**Root cause — `echo_ready_thresholds` returns zero thresholds for n ≤ 3:** [1](#0-0) 

```rust
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    if n <= 3 {
        return (0, 0);   // ← echo_t = 0, ready_t = 0
    }
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
}
```

With `echo_t = 0` and `ready_t = 0`, the three threshold comparisons in `reliable_broadcast_receive_all` all fire after receiving a **single** message: [2](#0-1) [3](#0-2) [4](#0-3) 

Each honest participant immediately delivers whatever `Send` value it first receives, without waiting for corroboration from any other participant.

**DKG uses `do_broadcast` for polynomial commitments:** [5](#0-4) 

```rust
let commitments_and_proofs_map = do_broadcast(
    &mut chan,
    &participants,
    me,
    (commitment, proof_of_knowledge),
)
.await?;
```

**DKG permits n = 3 with threshold = 2:** [6](#0-5) 

`assert_key_invariants` accepts any `n ≥ 2` and `threshold ≥ 2`, so a 3-party DKG is a fully supported configuration.

**Concrete attack (n = 3: honest A, honest B, malicious M):**

1. **Round 1 (session IDs):** M broadcasts the same session ID to A and B (consistent), so both compute the same `session_id` hash.
2. **Round 2 (commitment hashes, plain `send_many`):** M sends `H(commitment_X)` to A and `H(commitment_Y)` to B. This round uses `chan.send_many`, not broadcast — no consistency guarantee. [7](#0-6) 

3. **Round 3 (commitments, `do_broadcast`):** M bypasses `reliable_broadcast_send` and uses `chan.send_private` to deliver `(commitment_X, proof_X)` to A and `(commitment_Y, proof_Y)` to B. With `echo_t = 0`, each honest participant immediately delivers the value it received without waiting for the other's echo.

4. **Verification passes for both:** A checks `H(commitment_X) == H(commitment_X)` ✓ and verifies `proof_X` against `commitment_X` ✓. B checks `H(commitment_Y) == H(commitment_Y)` ✓ and verifies `proof_Y` against `commitment_Y` ✓. [8](#0-7) 

5. **Inconsistent public keys:** A computes `vk_A = commit_A + commit_B + commit_X` while B computes `vk_B = commit_A + commit_B + commit_Y`. Since `commit_X ≠ commit_Y`, `vk_A ≠ vk_B`.

6. **`broadcast_success` does not catch this:** Both A and B broadcast `(true, session_id)` with the same `session_id` (step 1 ensured this). The final consistency check only verifies session IDs and success votes — it does not compare public keys. [9](#0-8) 

---

### Impact Explanation

Honest parties A and B complete DKG holding different `public_key` values in their `KeygenOutput`. Any subsequent threshold signing round will fail or produce invalid signatures, because the participants disagree on the group public key. Reshare and refresh operations built on top of the corrupted DKG output will propagate the inconsistency. This matches the allowed High impact: **Corruption of DKG outputs so honest parties accept inconsistent public keys**.

---

### Likelihood Explanation

A 3-party threshold-2 configuration is the smallest meaningful threshold setup and is commonly deployed. Any single malicious participant in such a group can execute this attack without any special capability beyond controlling its own network messages — a standard assumption for a Byzantine adversary. The attack requires no cryptographic breaks, no side channels, and no external dependencies.

---

### Recommendation

1. **Enforce a minimum participant count** that guarantees non-zero echo-broadcast thresholds. The standard echo-broadcast security bound requires `n ≥ 3f + 1`; for `f = 1` this means `n ≥ 4`. Reject DKG initialization when `n ≤ 3` if Byzantine tolerance is required.
2. **Alternatively**, replace the zero-threshold path with a direct all-to-all consistency check for small `n`, where every participant explicitly confirms it received the same value as every other participant before proceeding.
3. **Add a final public-key consistency broadcast** at the end of `do_keyshare` so that all participants verify they derived the same `verifying_key` before returning `KeygenOutput`.

---

### Proof of Concept

```
Participants: A (honest), B (honest), M (malicious), n=3, threshold=2
echo_t = 0, ready_t = 0  (from echo_ready_thresholds(3))

Round 3 broadcast for M's commitment:
  M → A: Send(commitment_X, proof_X)   [via send_private]
  M → B: Send(commitment_Y, proof_Y)   [via send_private]

A processes Send(commitment_X):
  A echoes Echo(commitment_X) to all
  A simulates own echo: data_echo[X] = 1 > 0 = echo_t  → sends Ready(X)
  A simulates own ready: data_ready[X] = 1 > 0 = ready_t → amplifies Ready(X)
  data_ready[X] = 1 > 0 = 2*ready_t → A DELIVERS commitment_X

B processes Send(commitment_Y):
  B echoes Echo(commitment_Y) to all
  B simulates own echo: data_echo[Y] = 1 > 0 = echo_t  → sends Ready(Y)
  B simulates own ready: data_ready[Y] = 1 > 0 = ready_t → amplifies Ready(Y)
  data_ready[Y] = 1 > 0 = 2*ready_t → B DELIVERS commitment_Y

A receives Echo(Y) and Ready(Y) from B → ignored (finish_ready=true for M's session)
B receives Echo(X) and Ready(X) from A → ignored (finish_ready=true for M's session)

Result:
  vk_A = sum_commitments([commit_A, commit_B, commitment_X])
  vk_B = sum_commitments([commit_A, commit_B, commitment_Y])
  vk_A ≠ vk_B  →  DKG produces inconsistent public keys
  broadcast_success passes (same session_id, both vote true)
  KeygenOutput returned with split public key
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

**File:** src/protocol/echo_broadcast.rs (L223-225)
```rust
                if state_sid.data_echo.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > echo_t
```

**File:** src/protocol/echo_broadcast.rs (L280-283)
```rust
                if state_sid.data_ready.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > ready_t
                    && !state_sid.finish_amplification
```

**File:** src/protocol/echo_broadcast.rs (L293-295)
```rust
                if state_sid.data_ready.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > 2 * ready_t
```

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

**File:** src/dkg.rs (L452-476)
```rust
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

        // in case the participant was new and it sent a polynomial of length
        // threshold -1 (because the zero term is not serializable)
        let full_commitment_i = insert_identity_if_missing(threshold, commitment_i);

        // add received full commitment
        all_full_commitments.put(p, full_commitment_i);
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
