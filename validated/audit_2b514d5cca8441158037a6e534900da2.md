### Title
Unvalidated Signing Commitments in FROST Presign Enable Split-View Attack Producing Inconsistent Presign Transcripts — (File: src/frost/mod.rs)

---

### Summary
The `do_presign` function in `src/frost/mod.rs` collects `SigningCommitments` from other participants via point-to-point channels without any broadcast-consistency check. A malicious participant can send distinct commitment pairs to different honest participants. Each honest participant then stores a different `commitments_map` in its `PresignOutput`. When those inconsistent outputs are consumed in the signing phase, participants compute different binding factors and challenges, producing incompatible signature shares. Honest parties silently accept the corrupted presign transcript and proceed to a signing round that is guaranteed to fail.

---

### Finding Description

In `do_presign` (lines 90–117 of `src/frost/mod.rs`):

```rust
// Collecting the commitments
for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
    commitments_map.insert(from.to_identifier()?, commitment);
}

Ok(PresignOutput {
    nonces,
    commitments_map,
})
``` [1](#0-0) 

Each honest participant independently receives commitments from every other participant over individual point-to-point channels. There is no echo-broadcast step (compare with `do_broadcast` used throughout `src/dkg.rs`) to guarantee that every participant receives the *same* commitment from a given sender. The received `SigningCommitments` values are inserted into `commitments_map` without any cryptographic validation or cross-participant consistency check.

The DKG protocol explicitly uses `do_broadcast` for all safety-critical messages:

```rust
let commitments_and_proofs_map = do_broadcast(
    &mut chan,
    &participants,
    me,
    (commitment, proof_of_knowledge),
)
.await?;
``` [2](#0-1) 

No equivalent broadcast protection exists for FROST presign commitments.

A malicious participant deviates from the honest `chan.send_many` call and instead issues separate `chan.send_private` calls with distinct `SigningCommitments` values targeted at each honest peer. Because `recv_from_others` collects messages per-sender without comparing them across recipients, each honest participant silently stores a different commitment for the malicious sender.

---

### Impact Explanation

Every honest participant's `PresignOutput.commitments_map` is a direct input to the FROST binding-factor computation in the subsequent signing round. Because the binding factor is `ρ_i = H(i, msg, B)` where `B` is the full commitment list, divergent `commitments_map` values produce divergent `ρ_i` values across honest participants. Their signature shares `z_i = d_i + e_i·ρ_i + λ_i·s_i·c` are therefore computed against different challenges, making them mutually incompatible. The aggregated signature fails verification.

Honest parties have accepted and stored an inconsistent presign transcript — matching the allowed High impact: *"Corruption of … presign … outputs so honest parties accept inconsistent … transcripts or unusable cryptographic outputs."*

---

### Likelihood Explanation

Any single participant in the FROST presign session can execute this attack. No special privilege, leaked key, or external assumption is required. The attacker only needs to send two different `SigningCommitments` structs — one per honest peer — at the same waitpoint. This is trivially achievable by any participant who controls their own network stack. The attack is deterministic and requires no brute force.

---

### Recommendation

Replace the bare `send_many` / `recv_from_others` pattern for commitment exchange in `do_presign` with the same `do_broadcast` (echo-broadcast) primitive already used in `do_keyshare`. Echo broadcast guarantees that if any honest participant accepts a value from sender M, every honest participant accepts the *same* value from M, eliminating the split-view condition.

```rust
// Replace:
chan.send_many(commit_waitpoint, &commitments)?;
for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
    commitments_map.insert(from.to_identifier()?, commitment);
}

// With:
let broadcast_map = do_broadcast(&mut chan, &participants, me, commitments).await?;
for p in participants.others(me) {
    let commitment = broadcast_map.index(p)?;
    commitments_map.insert(p.to_identifier()?, *commitment);
}
```

---

### Proof of Concept

1. Honest participants A, B, and malicious participant M enter `do_presign`.
2. A and B call `chan.send_many(commit_waitpoint, &commitments)` — sending the same commitment to all.
3. M deviates: calls `chan.send_private(commit_waitpoint, A, &commitments_for_A)` and `chan.send_private(commit_waitpoint, B, &commitments_for_B)` with `commitments_for_A ≠ commitments_for_B`.
4. `recv_from_others` on A's side returns M's entry as `commitments_for_A`; on B's side as `commitments_for_B`.
5. Both A and B return `Ok(PresignOutput { nonces, commitments_map })` — no error is raised.
6. In the signing phase, A computes binding factor `ρ_M = H(M, msg, B_A)` and B computes `ρ_M = H(M, msg, B_B)` where `B_A ≠ B_B`.
7. A and B produce signature shares `z_A`, `z_B` computed against different challenges; the coordinator's aggregated `z = z_A + z_B + z_M` fails signature verification.
8. Signing is permanently blocked for this presign session; honest parties have silently accepted inconsistent presign transcripts. [3](#0-2) [4](#0-3)

### Citations

**File:** src/frost/mod.rs (L100-116)
```rust
    // Creating two commitments and corresponding nonces
    let (nonces, commitments) = commit(&signing_share, &mut rng);
    commitments_map.insert(me.to_identifier()?, commitments);

    let commit_waitpoint = chan.next_waitpoint();
    // Sending the commitments to all
    chan.send_many(commit_waitpoint, &commitments)?;

    // Collecting the commitments
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }

    Ok(PresignOutput {
        nonces,
        commitments_map,
    })
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
