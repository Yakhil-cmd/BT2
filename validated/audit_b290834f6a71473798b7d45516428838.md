### Title
Malicious CKD Participant Can Corrupt Coordinator's Derived Key Output Without Detection - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
In `do_ckd_coordinator`, the coordinator blindly aggregates `(big_y, big_c)` group elements received from all participants with no cryptographic verification of their correctness. A single malicious participant can substitute arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that produces an incorrect confidential derived key when unmasked by the client.

### Finding Description
The `do_ckd_coordinator` function receives each participant's `CKDOutput` and unconditionally adds the values together:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant `i` is supposed to compute and send:
- `norm_big_y_i = λ_i · y_i · G`
- `norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

where `y_i` is a fresh random blinding scalar, `x_i` is the participant's private share, and `λ_i` is the Lagrange coefficient. The coordinator aggregates these into `(Y, C)` and the client unmasks via `C − a · Y = msk · H(pk ‖ app_id)`.

There is no proof-of-correct-formation, no commitment, and no consistency check on the received `(big_y, big_c)` values. A malicious participant can send any pair of group elements `(big_y', big_c')` in place of their honest contribution. The coordinator adds them without question, producing a corrupted aggregate `(Y', C')`. The client then unmasks to an incorrect value:

```
C' − a · Y' = msk · H(pk ‖ app_id) + Δ_c − a · Δ_y
```

where `Δ_c = big_c' − big_c_honest` and `Δ_y = big_y' − big_y_honest` are attacker-chosen offsets. The derived key is permanently wrong for that `app_id`.

Contrast this with the DKG protocol in `src/dkg.rs`, which validates every received share against a committed polynomial (`validate_received_share`, line 259) and verifies proofs of knowledge (`verify_proof_of_knowledge`, line 172). The CKD protocol has no equivalent safeguard. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The coordinator is the sole recipient of the aggregated `CKDOutput`. It outputs a `CKDOutput` that is structurally valid (two non-zero G1 points) but cryptographically incorrect. The client has no way to detect the corruption: it receives `(Y', C')`, computes `C' − a · Y'`, and obtains a value that is not `msk · H(pk ‖ app_id)`. Any downstream use of the derived key (e.g., decryption, authentication) silently fails. The correct key for that `(pk, app_id)` pair is permanently unrecoverable from this protocol run. [4](#0-3) [5](#0-4) 

### Likelihood Explanation
**High.** Any single participant in the CKD protocol can mount this attack. No special knowledge, no colluding parties, and no cryptographic capability beyond basic group arithmetic is required. The attacker simply sends `(G, G)` or any other pair of group elements instead of their honest contribution. The attack is undetectable by the coordinator and by the client. [6](#0-5) 

### Recommendation
Each participant must accompany their `(norm_big_y, norm_big_c)` submission with a zero-knowledge proof of correct formation. Concretely, participant `i` should prove:

1. Knowledge of `y_i` such that `big_y_i = y_i · G` (a standard Schnorr PoK).
2. That `big_c_i = x_i · H(pk ‖ app_id) + y_i · app_pk`, where `x_i` is consistent with the public polynomial commitment established during DKG (i.e., `x_i · G` equals the participant's public share).

The coordinator must verify both proofs before incorporating any participant's contribution into the aggregate. This mirrors the pattern already used in `do_keyshare` where `verify_proof_of_knowledge` and `validate_received_share` are called for every participant before their data is used. [7](#0-6) 

### Proof of Concept

1. Participants `{p_1, p_2, p_3}` run the CKD protocol with coordinator `p_1`.
2. Malicious participant `p_2` intercepts the protocol at `do_ckd_participant` and instead of computing the correct `(norm_big_y, norm_big_c)` via `compute_signature_share`, sends `(G1::generator(), G1::generator())` to the coordinator.
3. `do_ckd_coordinator` receives this pair and adds it to the running aggregate without any check (lines 53–54).
4. The coordinator outputs `CKDOutput { big_y: Y + G, big_c: C + G }`.
5. The client calls `ckd_output.unmask(app_sk)` and computes `(C + G) − app_sk · (Y + G) = msk · H(pk ‖ app_id) + G − app_sk · G = msk · H(pk ‖ app_id) + (1 − app_sk) · G`.
6. The result is not `msk · H(pk ‖ app_id)`. The correct confidential derived key is unrecoverable from this run. [8](#0-7) [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L17-33)
```rust
fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}
```

**File:** src/confidential_key_derivation/protocol.rs (L35-57)
```rust
async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
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

**File:** src/confidential_key_derivation/protocol.rs (L148-181)
```rust
fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(ElementG1, ElementG1), ProtocolError> {
    // Ensures the value is zeroized on drop
    let private_share = Zeroizing::new(key_pair.private_share);

    // y <- ZZq* , Y <- y * G
    let y = Scalar::random(rng);

    // Ensures the value is zeroized on drop
    let y = Zeroizing::new(super::scalar_wrapper::ScalarWrapper(y));

    let big_y = ElementG1::generator() * y.0;

    // H(pk || app_id) when H is a random oracle
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;

    // Compute  λi := λi(0)
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

**File:** src/confidential_key_derivation/mod.rs (L52-56)
```rust
    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
