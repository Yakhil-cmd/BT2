### Title
Malicious Participant Causes Unattributed `InvalidCommitmentHash` Abort, Enabling Permanent Denial of Key Generation — (`src/dkg.rs`)

---

### Summary

A malicious participant can send `hash(C')` in round 2 and then broadcast a different commitment `C` in round 3. Every honest party will abort with `ProtocolError::InvalidCommitmentHash`. Because that error variant carries **no participant identifier**, honest parties cannot determine who misbehaved, cannot exclude the culprit, and the attack can be repeated indefinitely across every DKG attempt.

---

### Finding Description

The DKG protocol in `do_keyshare` proceeds in two relevant steps:

**Round 2 — hash commitment sent point-to-point:** [1](#0-0) 

Each participant computes `commitment_hash = H(me, commitment, session_id)` and sends it to all others via `chan.send_many`.

**Round 4 — commitment verified against stored hash:** [2](#0-1) 

`verify_commitment_hash` recomputes `H(p, commitment_i, session_id)` and compares it to the stored hash. If they differ, it returns: [3](#0-2) 

The returned error is the bare `InvalidCommitmentHash` variant: [4](#0-3) 

**No participant is named in this error.** Contrast with every other misbehaviour check in the same file, all of which embed the culprit's identity: [5](#0-4) 

Because `verify_commitment_hash` is called inside a `for p in participants.others(me)` loop and the result is immediately propagated with `?`, the first mismatch aborts the entire protocol for the calling honest party — and the identity of `p` that triggered the failure is discarded.

---

### Impact Explanation

A single malicious participant can:

1. Compute any `hash(C')` where `C' ≠ C` and send it in round 2.
2. Broadcast the valid commitment `C` (with a valid proof of knowledge) in round 3.
3. Every honest party reaches `verify_commitment_hash`, detects the mismatch, and returns `Err(InvalidCommitmentHash)` — aborting key generation.
4. Because the error carries no participant ID, honest parties cannot identify the culprit, cannot exclude them, and cannot make progress.
5. The attacker repeats the attack in every subsequent DKG session, achieving **permanent denial of key generation**.

This matches the allowed High impact: *"Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions."*

---

### Likelihood Explanation

The attack requires no cryptographic capability — only the ability to participate in a DKG session and send an arbitrary 32-byte hash value in round 2. Any participant in the protocol can execute it. The protocol already defends against analogous misbehaviour (wrong proof of knowledge, wrong secret share) by naming the culprit; the omission here is a straightforward implementation gap, not a design trade-off.

---

### Recommendation

Change `InvalidCommitmentHash` to carry the offending participant, mirroring `InvalidProofOfKnowledge(Participant)` and `InvalidSecretShare(Participant)`:

```rust
// errors.rs
#[error("the sent commitment_hash of participant {0:?} does not equal the hash of the commitment")]
InvalidCommitmentHash(Participant),
```

Update `verify_commitment_hash` to accept and return the participant:

```rust
// dkg.rs  verify_commitment_hash
if *actual_commitment_hash != commitment_hash {
    return Err(ProtocolError::InvalidCommitmentHash(participant));
}
```

This lets callers identify and exclude the malicious participant, consistent with how every other misbehaviour is handled in `do_keyshare`.

---

### Proof of Concept

```
Setup: 3 participants P1 (honest), P2 (honest), P3 (malicious), threshold = 2.

Round 2:
  P3 computes C  = its real commitment
  P3 computes C' = any different commitment
  P3 sends hash(P3, C', session_id) to P1 and P2   ← mismatched hash

Round 3:
  P3 broadcasts (C, proof_of_knowledge_for_C)       ← valid proof, wrong hash

Round 4 (at P1 and P2):
  verify_proof_of_knowledge(P3, C, proof) → Ok(())  ← passes
  verify_commitment_hash(P3, C, all_hashes)
    computes H(P3, C, session_id)
    compares to stored H(P3, C', session_id)
    → Err(InvalidCommitmentHash)                    ← no participant named

Result: P1 and P2 both abort. Neither knows P3 is the culprit.
        P3 repeats this in every subsequent session → permanent DoS.
```

### Citations

**File:** src/dkg.rs (L228-235)
```rust
) -> Result<(), ProtocolError> {
    let actual_commitment_hash = all_hash_commitments.index(participant)?;
    let commitment_hash =
        domain_separate_hash(domain_separator, &(&participant, &commitment, &session_id))?;
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
    Ok(())
```

**File:** src/dkg.rs (L410-415)
```rust
    let commitment_hash =
        domain_separate_hash(&mut domain_separator, &(&me, &commitment, &session_id))?;

    // Step 2.9
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &commitment_hash)?;
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

**File:** src/errors.rs (L40-41)
```rust
    #[error("the sent commitment_hash does not equal the hash of the commitment")]
    InvalidCommitmentHash,
```

**File:** src/errors.rs (L58-68)
```rust
    #[error("the proof of knowledge of participant {0:?} is not valid")]
    InvalidProofOfKnowledge(Participant),

    #[error("participant {0:?} sent an invalid secret share")]
    InvalidSecretShare(Participant),

    #[error("the element you are trying to construct is malformed")]
    MalformedElement,

    #[error("detected a malicious participant {0:?}")]
    MaliciousParticipant(Participant),
```
