### Title
Equivocating Commitment Delivery via Degenerate Echo-Broadcast Allows Inconsistent Public Keys — (`src/dkg.rs`, `src/protocol/echo_broadcast.rs`)

---

### Summary

A single malicious participant in a 3-party DKG/reshare/refresh session can deliver different `(commitment, proof_of_knowledge)` pairs to each honest party. Because `echo_ready_thresholds` returns `(0, 0)` for `n ≤ 3`, the echo-broadcast primitive provides zero Byzantine fault tolerance at that group size. The commitment-hash pre-commitment sent in the prior round is transmitted via plain `send_many` (not echo-broadcast), so the attacker can also tailor the hash to match whichever commitment each honest party receives. Both honest parties pass every verification check and converge on different public keys, yet both accept the protocol as successful.

---

### Finding Description

**Step 1 — Commitment hash is sent via unauthenticated point-to-point send.**

In `do_keyshare`, the commitment hash is broadcast with a plain `send_many`: [1](#0-0) 

`send_many` delivers one message per recipient with no consistency guarantee. A malicious participant M can send `hash_1 = H(commitment_1)` to honest party A and `hash_2 = H(commitment_2)` to honest party B.

**Step 2 — The actual commitment is sent via `do_broadcast`, but `do_broadcast` is not Byzantine-safe for n = 3.** [2](#0-1) 

`do_broadcast` calls `reliable_broadcast_receive_all`, whose thresholds come from: [3](#0-2) 

For `n = 3`, both `echo_t` and `ready_t` are `0`. The delivery condition is `count > 0`, meaning a single echo or ready vote suffices. When M sends `commitment_1` to A and `commitment_2` to B:

- A echoes `commitment_1`, accumulates 1 echo vote (its own simulated echo), satisfies `> 0`, sends `Ready(commitment_1)`, accumulates 1 ready vote, satisfies `> 0`, and **delivers `commitment_1`**.
- B echoes `commitment_2`, follows the same path, and **delivers `commitment_2`**.

Each honest party sets `finish_echo = true` and `finish_ready = true` for M's session before it can observe the other party's conflicting echo/ready, so the inconsistency is never detected.

**Step 3 — `verify_commitment_hash` passes independently for each honest party.** [4](#0-3) [5](#0-4) 

A checks `H(commitment_1) == hash_1` — passes.  
B checks `H(commitment_2) == hash_2` — passes.  
Neither party can detect the equivocation.

**Step 4 — `verify_proof_of_knowledge` also passes for both.**

M generates two valid Schnorr proofs, one for each commitment's constant term. Both proofs verify correctly against their respective commitments.

**Step 5 — Public keys diverge; `broadcast_success` does not catch it.**

A computes `vk_A = commit_A + commit_B + commitment_1`; B computes `vk_B = commit_A + commit_B + commitment_2`. Since `commitment_1 ≠ commitment_2`, `vk_A ≠ vk_B`. The final step: [6](#0-5) 

only checks that all parties broadcast `(true, session_id)` — it does not verify that all parties derived the same public key. Both A and B broadcast success and return `KeygenOutput` with different `public_key` fields.

---

### Impact Explanation

Honest parties accept inconsistent public keys and signing shares after a completed DKG/reshare/refresh. Any subsequent threshold signing attempt will fail or produce signatures that only verify under one party's view of the public key, permanently breaking the signing capability for the group. This matches the **High** impact category: *"Corruption of DKG, reshare, refresh outputs so honest parties accept inconsistent public keys or unusable cryptographic outputs."*

---

### Likelihood Explanation

The minimum group size is `n = 2` (enforced by `assert_key_invariants`), and `n = 3` is the smallest group where two honest parties can disagree. Any deployment with exactly 3 participants and 1 malicious member is vulnerable. The attacker needs only to be a registered participant and control their own message delivery — no cryptographic break is required.

---

### Recommendation

1. **Send the commitment hash via `do_broadcast` instead of `send_many`**, or include the commitment hash inside the echo-broadcast payload so its consistency is guaranteed by the same mechanism as the commitment itself.
2. **Fix `echo_ready_thresholds` for `n = 3`**: the current `(0, 0)` thresholds provide no equivocation resistance. For `n = 3` with up to 1 Byzantine party the standard Bracha thresholds require `n ≥ 3f + 1`; since `3 < 3·1 + 1 = 4`, the protocol should either refuse to run with `n = 3` under a Byzantine adversary model, or document that `n = 3` provides no equivocation safety and enforce `n ≥ 4` in `assert_key_invariants`.
3. **Add a final consistency broadcast of the derived public key** so that honest parties abort if their computed `verifying_key` values differ.

---

### Proof of Concept

```
Participants: A (honest), B (honest), M (malicious), n=3, threshold=2

Round 1 — session_id broadcast (do_broadcast, also degenerate for n=3):
  M sends my_session_id_1 to A, my_session_id_2 to B
  → session_id_A ≠ session_id_B  (optional; M may keep these equal)

Round 2 — commitment hash (send_many, no consistency):
  M computes commitment_1, commitment_2 (two distinct polynomials * G)
  M → A: hash_1 = H(domain_sep, M, commitment_1, session_id)
  M → B: hash_2 = H(domain_sep, M, commitment_2, session_id)

Round 3 — commitment + proof (do_broadcast, thresholds (0,0)):
  M → A: Send(commitment_1, proof_1)   [proof_1 valid for commitment_1]
  M → B: Send(commitment_2, proof_2)   [proof_2 valid for commitment_2]
  A echoes commitment_1, delivers commitment_1 (1 echo > 0)
  B echoes commitment_2, delivers commitment_2 (1 echo > 0)

Round 4 — verification at each honest party:
  A: verify_proof_of_knowledge(commitment_1, proof_1) → OK
     verify_commitment_hash(commitment_1, hash_1)     → OK
  B: verify_proof_of_knowledge(commitment_2, proof_2) → OK
     verify_commitment_hash(commitment_2, hash_2)     → OK

Round 5 — share distribution:
  M → A: f_1(A)  [consistent with commitment_1]
  M → B: f_2(B)  [consistent with commitment_2]
  validate_received_share passes for both.

Final state:
  A.public_key = vk_A  (includes commitment_1 for M)
  B.public_key = vk_B  (includes commitment_2 for M)
  vk_A ≠ vk_B
  broadcast_success passes for both → both return Ok(KeygenOutput)
```

Honest parties A and B hold irreconcilably different public keys after a protocol run that both consider successful.

### Citations

**File:** src/dkg.rs (L222-236)
```rust
fn verify_commitment_hash<C: Ciphersuite>(
    session_id: &HashOutput,
    participant: Participant,
    domain_separator: &mut DomainSeparator,
    commitment: &VerifiableSecretSharingCommitment<C>,
    all_hash_commitments: &ParticipantMap<'_, HashOutput>,
) -> Result<(), ProtocolError> {
    let actual_commitment_hash = all_hash_commitments.index(participant)?;
    let commitment_hash =
        domain_separate_hash(domain_separator, &(&participant, &commitment, &session_id))?;
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
    Ok(())
}
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

**File:** src/dkg.rs (L433-441)
```rust
    // Broadcast the commitment and the proof of knowledge
    // Step 3.2 and 4.1
    let commitments_and_proofs_map = do_broadcast(
        &mut chan,
        &participants,
        me,
        (commitment, proof_of_knowledge),
    )
    .await?;
```

**File:** src/dkg.rs (L462-469)
```rust
        // verify that the commitment sent hashes to the received commitment_hash in round 1
        verify_commitment_hash(
            &session_id,
            p,
            &mut commit_domain_separator.clone(), // you want to have the same state
            commitment_i,
            &all_hash_commitments,
        )?;
```

**File:** src/dkg.rs (L530-531)
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
