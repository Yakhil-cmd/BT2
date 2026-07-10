Based on my analysis of the code, here is my determination:

---

### Title
Commitment Hash Equivocation via `send_many` Enables Targeted Abort of Honest DKG Participants — (`src/dkg.rs`)

### Summary
A malicious DKG participant can send a different `commitment_hash` to each honest party in Round 2.9, then broadcast the real commitment via echo broadcast. Honest parties that received a mismatched hash will abort with `InvalidCommitmentHash` while others succeed, permanently splitting the honest party set and preventing DKG completion.

### Finding Description

In `do_keyshare`, the commitment hash is distributed using `send_many` (a plain peer-to-peer send with no consistency guarantee): [1](#0-0) 

`send_many` is explicitly documented as having **no security guarantees** — it is a peer-to-peer send to multiple receivers with no agreement property: [2](#0-1) 

In contrast, the actual commitment is sent via `do_broadcast` (echo broadcast), which guarantees all honest parties receive the same value: [3](#0-2) 

After receiving the commitment via echo broadcast, each honest party calls `verify_commitment_hash`, which checks the commitment against the hash it received in the `send_many` round: [4](#0-3) 

The verification function computes `H(commitment)` and compares it to `all_hash_commitments[p]` — the value received via the unprotected `send_many`: [5](#0-4) 

**Attack path:**
1. Malicious participant M computes commitment `C` and correct hash `h = H(M, C, sid)`.
2. M sends `h` to P1 (correct) and `h' ≠ h` to P2 (wrong) via the `send_many` round.
3. M broadcasts `C` via echo broadcast — all honest parties receive the same `C`.
4. P1 verifies `H(C) == h` → passes, continues.
5. P2 verifies `H(C) == h'` → fails, returns `Err(ProtocolError::InvalidCommitmentHash)`.

P1 and P2 now hold inconsistent views of M's honesty. P1 has no evidence of equivocation; P2 has aborted. There is no cross-party equivocation-detection mechanism in the protocol.

### Impact Explanation

A single malicious participant can selectively abort any subset of honest parties in every DKG session. Because P1 (which succeeded) has no evidence that M equivocated, honest parties cannot reach consensus on excluding M. M can repeat this attack in every subsequent session, permanently preventing DKG from completing with the full honest party set. This matches the **High** impact: *Permanent denial of key generation for honest parties under valid protocol inputs and documented trust assumptions* (MaxFaulty = ⌊(N−1)/3⌋).

### Likelihood Explanation

The attack requires only that a participant implement a modified protocol that sends different byte values to different peers at `wait_round_1`. No cryptographic assumptions need to be broken. The `send_many` primitive provides no consistency guarantee by design, and the protocol spec (Step 2.9 in `docs/dkg.md`) does not mark this step with a reliable broadcast symbol, confirming the gap is structural. [6](#0-5) 

### Recommendation

Replace the `send_many`/`recv_from_others` pattern for the commitment hash round with `do_broadcast` (echo broadcast). This ensures all honest parties receive the same hash from each sender before the commitment is revealed, closing the equivocation window. The commitment hash round should be treated with the same consistency requirement as the commitment itself.

### Proof of Concept

Simulate a 3-party DKG where participant M (index 2) sends:
- `hash_A = H(M, C, sid)` (correct) to P1
- `hash_B = [0u8; 32]` (wrong) to P2

Then M broadcasts `C` via echo broadcast normally. Assert:
- P1's `do_keyshare` returns `Ok(_)`
- P2's `do_keyshare` returns `Err(ProtocolError::InvalidCommitmentHash)`

This is directly testable by constructing a mock `SharedChannel` that intercepts and modifies the outgoing `send_many` message at `wait_round_1` before delivery to P2.

### Citations

**File:** src/dkg.rs (L229-234)
```rust
    let actual_commitment_hash = all_hash_commitments.index(participant)?;
    let commitment_hash =
        domain_separate_hash(domain_separator, &(&participant, &commitment, &session_id))?;
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
```

**File:** src/dkg.rs (L414-426)
```rust
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

**File:** src/dkg.rs (L463-469)
```rust
        verify_commitment_hash(
            &session_id,
            p,
            &mut commit_domain_separator.clone(), // you want to have the same state
            commitment_i,
            &all_hash_commitments,
        )?;
```

**File:** docs/network-layer.md (L23-24)
```markdown
- **`send_many`**: Sends a message to participants except the sender itself. This is a peer-to-peer sending with no security guarantees used by one sender in destination to multiple receiver.

```

**File:** docs/dkg.md (L88-94)
```markdown

2.9 Each $P_i$ sends $h_i$ to every participant

### Round 3

3.1 Each $P_i$ waits to receive $h_j$ from every participant $P_j$.

```
