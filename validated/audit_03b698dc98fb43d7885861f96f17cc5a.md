### Title
Missing Validation of Participant-Provided CKD Shares Allows Malicious Participant to Corrupt Coordinator Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary
The `do_ckd_coordinator` function in `src/confidential_key_derivation/protocol.rs` blindly accumulates `(norm_big_y, norm_big_c)` values received from every participant with no proof of correctness. A single malicious participant can send arbitrary group elements, causing the coordinator to compute and accept a corrupted `CKDOutput` that does not correspond to the honest threshold key.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's share and sums them directly:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

Each honest participant computes their share as:

```rust
let norm_big_y = big_y * lambda_i;          // λᵢ · yᵢ · G
let norm_big_c = big_c * lambda_i;          // λᵢ · (xᵢ · H(pk,app_id) + yᵢ · app_pk)
``` [2](#0-1) 

No zero-knowledge proof, commitment binding, or consistency check is attached to the message. The coordinator has no mechanism to verify that the received `big_c` was formed using the participant's actual key share `xᵢ` and a freshly chosen `yᵢ`. Any group element is accepted and added unconditionally.

By contrast, the DKG protocol enforces proof-of-knowledge of the secret coefficient, commitment hashes, and per-share Feldman verification before accepting any participant contribution: [3](#0-2) 

No equivalent validation exists in the CKD path.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The final confidential key is recovered as:

```
K = C − app_sk · Y  =  msk · H(pk, app_id)
```

If a malicious participant `j` sends `big_c_j = 0` (the group identity) instead of their correct share, the coordinator computes:

```
C_corrupt = Σ_{i≠j} λᵢ · (xᵢ · H + yᵢ · app_pk)
```

which is missing participant `j`'s key contribution. The recovered key `K_corrupt ≠ msk · H(pk, app_id)`. The coordinator outputs and accepts this corrupted `CKDOutput` with no error, delivering an unusable derived key to the application.

More generally, the malicious participant can send any `(big_y', big_c')` to bias the output to an attacker-chosen value, making the derived key entirely unpredictable or controlled.

---

### Likelihood Explanation

**High.** Any participant in the CKD session is a valid attacker. The attack requires only that the malicious participant serialize and send a crafted group element in place of their honest share — a single-message deviation that is trivially executable and undetectable by the coordinator under the current protocol. No special capability, leaked key, or external dependency is required.

---

### Recommendation

Require each participant to attach a non-interactive zero-knowledge proof (e.g., a Chaum-Pedersen proof) demonstrating that `big_c` was formed as `λᵢ · (xᵢ · H(pk, app_id) + yᵢ · app_pk)` using the same `xᵢ` committed to during DKG and the same `yᵢ` used to produce `big_y`. The coordinator must verify all proofs before accumulating any share, analogous to how `verify_proof_of_knowledge` and `validate_received_share` gate every DKG contribution. [4](#0-3) 

---

### Proof of Concept

1. An honest DKG completes; all participants hold valid shares `xᵢ` of `msk`.
2. A CKD session is initiated with `app_id` and `app_pk`.
3. Malicious participant `j` computes their honest `(norm_big_y_j, norm_big_c_j)` but instead sends `(ElementG1::identity(), ElementG1::identity())` to the coordinator.
4. The coordinator's loop at lines 50–55 adds the identity elements, effectively dropping participant `j`'s key contribution.
5. The coordinator outputs `CKDOutput::new(norm_big_y, norm_big_c)` where `norm_big_c` is missing `λⱼ · xⱼ · H(pk, app_id)`.
6. The application decrypts the output and obtains `K_corrupt = (msk − λⱼ · xⱼ) · H(pk, app_id)`, which is not the intended confidential key. No error is raised; the honest coordinator accepts the corrupted output.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L177-181)
```rust
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
```

**File:** src/dkg.rs (L259-286)
```rust
fn validate_received_share<C: Ciphersuite>(
    me: Participant,
    from: Participant,
    signing_share_from: &SigningShare<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> Result<(), ProtocolError> {
    let id = me.to_identifier::<C>()?;

    // The verification is exactly the same as the regular SecretShare verification;
    // however the required components are in different places.
    // Build a temporary SecretShare so what we can call verify().
    let secret_share = SecretShare::new(id, *signing_share_from, commitment.clone());

    // Verify the share. We don't need the result.
    // Identify the culprit if an InvalidSecretShare error is returned.
    secret_share.verify().map_err(|e| {
        if let Error::InvalidSecretShare { .. } = e {
            ProtocolError::InvalidSecretShare(from)
        } else {
            ProtocolError::AssertionFailed(format!(
                "could not
            extract the verification key matching the secret
            share sent by {from:?}"
            ))
        }
    })?;
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
