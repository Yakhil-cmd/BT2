### Title
Single Malicious Participant Aborts Entire DKG for All Honest Parties via Invalid Proof of Knowledge - (File: `src/dkg.rs`)

### Summary
A single malicious participant in the DKG (or reshare/refresh) protocol can permanently abort the entire key generation for all honest participants by broadcasting an invalid proof of knowledge or invalid commitment hash. Because the protocol iterates over every participant's contribution and returns an error on the first failure, one bad actor poisons the entire round — a direct structural analog to the batch-purchase DoS in the reference report.

### Finding Description
In `do_keyshare` (`src/dkg.rs`), Round 4 iterates over every other participant and calls `verify_proof_of_knowledge` and `verify_commitment_hash` with the `?` operator:

```rust
for p in participants.others(me) {
    let (commitment_i, proof_i) = commitments_and_proofs_map.index(p)?;
    verify_proof_of_knowledge(...)?;   // ← aborts entire DKG on first failure
    verify_commitment_hash(...)?;      // ← aborts entire DKG on first failure
    all_full_commitments.put(p, full_commitment_i);
}
``` [1](#0-0) 

Similarly, Round 5 calls `validate_received_share` with `?` for every received signing share:

```rust
for (from, signing_share_from) in
    recv_from_others(&chan, wait_round_3, &participants, me).await?
{
    validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
    my_signing_share = my_signing_share + signing_share_from.to_scalar();
}
``` [2](#0-1) 

The commitments are distributed via `do_broadcast` (reliable broadcast), which guarantees that **all** honest participants receive the **same** data from each sender. [3](#0-2) 

Therefore, if malicious participant P_m broadcasts an invalid proof of knowledge, every honest participant receives the identical invalid proof, every honest participant's `verify_proof_of_knowledge` call returns `Err(ProtocolError::InvalidProofOfKnowledge(P_m))`, and every honest participant's `do_keyshare` future terminates with an error — aborting the DKG for the entire group simultaneously.

There is no mechanism to skip the offending participant and continue with the remaining honest participants. The `broadcast_success` function, which is the final synchronisation step, is never reached; its comment even acknowledges an intended but unimplemented error-signalling path:

```rust
/// This function takes err as input.
/// If err is None then broadcast success
/// otherwise, broadcast failure
async fn broadcast_success(...) -> Result<(), ProtocolError> {
    // broadcast node me succeded
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
``` [4](#0-3) 

The function signature has no `err` parameter and always broadcasts `true`, confirming the failure-signalling path was never implemented.

### Impact Explanation
The README explicitly documents: *"our DKG/Resharing protocol can only tolerate n/3 malicious parties where n is the total number of parties."* [5](#0-4) 

A single malicious participant (1 ≤ n/3 for any n ≥ 3) can abort the DKG for all honest parties, violating this documented liveness guarantee. The same root cause applies to `do_reshare` (which calls `do_keyshare`) and to any protocol that depends on a completed DKG output (signing, presigning, CKD). This maps to **High: Permanent denial of key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions**.

### Likelihood Explanation
Any participant who is admitted to the DKG participant list can trigger this by sending a syntactically valid but cryptographically invalid proof of knowledge (e.g., a random `Signature<C>` that does not satisfy the Schnorr equation). No special privilege, leaked key, or external dependency is required. The attack is repeatable across every DKG attempt that includes the malicious participant.

### Recommendation
Adopt the same structural fix suggested in the reference report: isolate per-participant failures instead of propagating them to abort the entire batch. Concretely:

1. Collect all participants' proofs before verifying any, then build a set of *disqualified* participants whose proofs fail.
2. If the disqualified set is non-empty but within the tolerated threshold, exclude those participants and continue with the remaining honest set.
3. Implement the missing error-signalling path in `broadcast_success` so that a participant that detects a local failure can broadcast `(false, session_id)` and allow peers to reach a consistent abort decision rather than hanging indefinitely.

### Proof of Concept
1. Run a DKG with participants `[P1, P2, P3]`, threshold 2.
2. P3 (malicious) constructs a `Signature<C>` with random `R` and `z` values that do not satisfy `R == G*z - vk_share * c`.
3. P3 sends this invalid proof via the reliable broadcast in Round 3.
4. Because `do_broadcast` guarantees consistent delivery, both P1 and P2 receive the same invalid proof from P3.
5. Both P1 and P2 execute `verify_proof_of_knowledge` → `internal_verify_proof_of_knowledge` → the Schnorr check at line 162 fails → `Err(ProtocolError::InvalidProofOfKnowledge(P3))` is returned.
6. Both P1 and P2's `do_keyshare` futures terminate with an error; neither reaches `broadcast_success`.
7. The DKG is aborted for all honest participants despite only 1 of 3 parties being malicious — within the documented n/3 = 1 tolerance. [6](#0-5) [7](#0-6)

### Citations

**File:** src/dkg.rs (L145-166)
```rust
fn internal_verify_proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: &mut DomainSeparator,
    participant: Participant,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: &Signature<C>,
) -> Result<(), ProtocolError> {
    // creates an identifier for the participant
    let id = participant.scalar::<C>();
    let vk_share = commitment
        .coefficients()
        .first()
        .ok_or_else(|| ProtocolError::AssertionFailed("Empty coefficient list".to_string()))?;

    let big_r = proof_of_knowledge.R();
    let z = proof_of_knowledge.z();
    let c = challenge::<C>(domain_separator, session_id, id, vk_share, big_r)?;
    if *big_r != <C::Group>::generator() * *z - vk_share.value() * c.to_scalar() {
        return Err(ProtocolError::InvalidProofOfKnowledge(participant));
    }
    Ok(())
}
```

**File:** src/dkg.rs (L302-338)
```rust
/// This function takes err as input.
/// If err is None then broadcast success
/// otherwise, broadcast failure
/// If during broadcast it receives an error then propagates it
/// This function is used in the final round of DKG
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

**File:** src/dkg.rs (L446-477)
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

        // in case the participant was new and it sent a polynomial of length
        // threshold -1 (because the zero term is not serializable)
        let full_commitment_i = insert_identity_if_missing(threshold, commitment_i);

        // add received full commitment
        all_full_commitments.put(p, full_commitment_i);
    }
```

**File:** src/dkg.rs (L514-528)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        // Step 5.3
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
    }
```

**File:** README.md (L157-163)
```markdown
* **🚨 Important 🚨:** Our DKG/Resharing protocol is the same for ECDSA, EdDSA
  and CKD but differs depending on the underlying elliptic curve instantiation.
  Internally, this DKG makes use of a reliable broadcast channel implemented for
  asynchronous peer-to-peer communication. Due to a fundamental impossibility
  theorem for asynchronous broadcast channel, our DKG/Resharing protocol can
  only tolerate $\frac{n}{3}$ malicious parties where $n$ is the total number of
  parties.
```
