### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly sums participant-provided `(big_y, big_c)` group elements with no cryptographic verification that each contribution was honestly computed. A single malicious participant can inject arbitrary values, causing all honest parties to accept a corrupted confidential derived key.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `(norm_big_y, norm_big_c)` and accumulates them unconditionally: [1](#0-0) 

The honest computation in `compute_signature_share` produces:

- `norm_big_y = lambda_i * y_i * G`
- `norm_big_c = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)` [2](#0-1) 

There is no zero-knowledge proof, commitment, or consistency check binding `big_c` to the participant's private share `x_i` and the claimed randomness `y_i` (represented by `big_y`). A malicious participant can send any `(big_y', big_c')` pair and the coordinator has no mechanism to detect the deviation.

This is the direct analog of the GammaVault spot-price issue: just as the collateral calculation consumed an unverified, manipulable on-chain value (spot price) instead of a robust one (TWAP), the CKD coordinator consumes unverified, participant-supplied group elements instead of verifiably correct contributions.

Contrast this with the DKG protocol, which does enforce correctness of participant contributions via proof-of-knowledge and commitment hashing: [3](#0-2) 

No equivalent verification exists in the CKD path.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The coordinator returns `Some(CKDOutput { big_y: Y_corrupted, big_c: C_corrupted })` with no error. The application that decrypts the output using `app_sk` derives:

```
C_corrupted - app_sk * Y_corrupted
  = msk * H(pk, app_id) + delta_c - app_sk * delta_y
```

Because the malicious participant does not know `app_sk`, the term `delta_c - app_sk * delta_y` is non-zero with overwhelming probability, so the derived confidential key is incorrect. The honest coordinator and all honest parties accept this corrupted output silently. [4](#0-3) 

---

### Likelihood Explanation

**Medium.** Requires a single malicious participant in the CKD session. The library's robust ECDSA scheme explicitly documents and defends against malicious participants, confirming this threat model is in scope. The CKD protocol offers no equivalent defense. [5](#0-4) 

---

### Recommendation

Attach a Sigma-protocol zero-knowledge proof (e.g., a Chaum-Pedersen proof) to each participant's `(big_y, big_c)` contribution, proving in zero-knowledge that:

- `big_y = y_i * G`
- `big_c = x_i * H(pk, app_id) + y_i * app_pk`

for the same `y_i`, without revealing `x_i` or `y_i`. The coordinator must verify this proof before adding the contribution to the running sum, mirroring the proof-of-knowledge verification already present in the DKG protocol. [6](#0-5) 

---

### Proof of Concept

1. All honest participants run `compute_signature_share` and send correct `(norm_big_y, norm_big_c)` to the coordinator.
2. Malicious participant `P_m` instead sends `(norm_big_y + delta_y, norm_big_c + delta_c)` for arbitrary non-zero `delta_y, delta_c` of their choice.
3. The coordinator sums all contributions:
   - `Y_final = Y_honest_sum + delta_y`
   - `C_final = C_honest_sum + delta_c`
4. The coordinator returns `Some(CKDOutput { big_y: Y_final, big_c: C_final })` — no error is raised.
5. The application decrypts: `C_final - app_sk * Y_final = msk * H(pk, app_id) + (delta_c - app_sk * delta_y)`.
6. Since `P_m` does not know `app_sk`, the residual `delta_c - app_sk * delta_y ≠ 0` with overwhelming probability, yielding an incorrect confidential key that honest parties silently accept. [7](#0-6)

### Citations

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

**File:** src/confidential_key_derivation/protocol.rs (L148-182)
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
}
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

**File:** src/dkg.rs (L452-469)
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
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L74-79)
```rust
    // To prevent split-view attacks documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during presigning must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }
```
