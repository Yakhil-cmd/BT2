### Title
Malicious Participant Can Corrupt CKD Output via Unverified Contributions to Coordinator — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly accumulates participant-supplied group elements without any cryptographic proof of correct computation. A single malicious participant can send arbitrary curve points, corrupting the final `CKDOutput` and causing the client to derive a wrong confidential key.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator receives a `CKDOutput` struct (`big_y`, `big_c`) from every other participant and unconditionally adds them to its running sum: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

There is no ZK proof, Pedersen commitment, or any other check that a participant's `big_c` was actually computed as `lambda_i * (x_i * H(pk, app_id) + y_i * A)` using their real private share `x_i`.

This is the direct analog of the external report's pattern: the DKG protocol (`do_keyshare`) **does** verify every participant's contribution via `verify_proof_of_knowledge` and `validate_received_share`: [2](#0-1) 

but the CKD protocol applies no equivalent check. The `compute_signature_share` function correctly applies the Lagrange coefficient: [3](#0-2) 

yet nothing prevents a malicious participant from skipping that computation entirely and sending hand-crafted points.

The final output is assembled and returned to the caller with no post-hoc consistency check: [4](#0-3) 

The `unmask` function on the client side then computes `big_c − a·big_y`: [5](#0-4) 

If either accumulated sum is wrong, the result diverges from `msk · H(pk, app_id)` by an attacker-controlled offset, producing a silently wrong confidential key.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

A malicious participant P_m sends `big_y' = δ_Y` and `big_c' = δ_C` (arbitrary group elements). The coordinator computes:

```
Y_total  = Σ_{i≠m} λ_i·y_i·G  +  δ_Y
C_total  = msk·H(pk,app_id)  +  Σ_{i≠m} λ_i·y_i·A  +  δ_C
```

`unmask(a)` then yields `msk·H(pk,app_id) + δ_C − a·δ_Y`, which is wrong for any `(δ_Y, δ_C) ≠ (0,0)`. The client has no way to detect the corruption because no expected value is published.

---

### Likelihood Explanation

**High.** Any single participant in the CKD session can trigger this. No cryptographic capability beyond participation in the protocol is required. The attacker only needs to deviate from the honest computation when sending their private message to the coordinator.

---

### Recommendation

Require each participant to attach a non-interactive ZK proof of correct computation alongside their `(big_y, big_c)` contribution — for example, a Schnorr proof that `big_c − app_pk·y_i = x_i · H(pk, app_id)` and `big_y = y_i · G` for the same `y_i`, without revealing `x_i` or `y_i`. The coordinator must verify all proofs before accumulating any contribution, mirroring the `verify_proof_of_knowledge` + `validate_received_share` pattern already present in `do_keyshare`. [6](#0-5) 

---

### Proof of Concept

1. All N participants call `ckd(participants, coordinator, me, key_pair, app_id, app_pk, rng)`.
2. Honest participants execute `compute_signature_share` and send the result to the coordinator via `chan.send_private`.
3. Malicious participant P_m instead sends `CKDOutput::new(G1::generator(), G1::generator())` — two arbitrary non-zero points — to the coordinator.
4. The coordinator's loop at lines 50–55 adds these points to `norm_big_y` and `norm_big_c` without complaint.
5. The returned `CKDOutput` is corrupted; `ckd_output.unmask(app_sk)` produces a value that differs from `msk · H(pk, app_id)` by `G1::generator() − app_sk · G1::generator()`.
6. The client silently uses the wrong derived key for all subsequent operations. [7](#0-6)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L44-57)
```rust
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    // Receive everyone's inputs and add them together
    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L176-181)
```rust
    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
```

**File:** src/dkg.rs (L143-166)
```rust
/// Verifies the proof of knowledge of the secret coefficients used to generate the
/// public secret sharing commitment.
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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
