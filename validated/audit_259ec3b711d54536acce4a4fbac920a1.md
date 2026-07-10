### Title
CKD Coordinator Accepts Unverified Participant Contributions, Enabling Malicious Participant to Corrupt Derived Confidential Key — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `do_ckd_coordinator` function in the Confidential Key Derivation (CKD) protocol collects `(norm_big_y, norm_big_c)` contributions from each participant and sums them without any zero-knowledge proof of correct computation. A malicious participant can substitute arbitrary group elements, causing the coordinator to assemble a corrupted `CKDOutput`. The TEE app then decrypts a wrong confidential key, permanently breaking its ability to use the derived secret for its intended purpose.

---

### Finding Description

The CKD protocol is designed so that each participant `i` computes:

- `norm_big_y_i = λ_i · y_i · G` (random ElGamal blinding factor)
- `norm_big_c_i = λ_i · (x_i · H(pk, app_id) + y_i · A)` (ElGamal encryption of the key-share contribution)

The coordinator sums all contributions to produce `(Y, C)`, which the TEE app decrypts as `s = C − a·Y = msk · H(pk, app_id)`.

In `do_ckd_coordinator`, lines 50–55, the coordinator performs this aggregation with no verification whatsoever:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

No proof is required that `big_y` and `big_c` were computed from the participant's actual key share `x_i` and the correct `app_pk`. Any participant can send arbitrary group elements.

This contrasts sharply with the DKG protocol, which enforces correctness of every participant's contribution through a Schnorr proof-of-knowledge, a commitment hash binding, and a Feldman share verification before accepting any material: [2](#0-1) 

The CKD protocol has no equivalent safeguard.

---

### Impact Explanation

A malicious participant sends `(norm_big_y', norm_big_c')` of their choosing instead of the correct values. The coordinator sums all contributions:

```
Y  = Σ λ_j · y_j · G  +  (norm_big_y'  − correct_norm_big_y_i)
C  = Σ λ_j · (x_j · H + y_j · A)  +  (norm_big_c' − correct_norm_big_c_i)
```

The TEE app decrypts `C − a·Y` and receives a value that is not `msk · H(pk, app_id)`. The derived confidential key is permanently wrong. The TEE app cannot recover the correct key without re-running the protocol with honest participants, and any data previously encrypted or authenticated under the expected key is irrecoverably inaccessible.

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.** [3](#0-2) 

---

### Likelihood Explanation

The attacker must be a legitimate participant in the MPC network (i.e., hold a valid key share and be included in the `participants` list). No external key material or privileged access is required beyond that role. The `recv_from_others` call accepts any value from any listed participant; there is no authentication of the *content* of the message, only of its sender identity. The attack is a single-round substitution with no detectable side-effect until the TEE app attempts to use the derived key. [4](#0-3) 

---

### Recommendation

Add a zero-knowledge proof of correct ElGamal encryption to each participant's contribution. Specifically, each participant should prove in zero-knowledge that:

1. `norm_big_y_i = λ_i · y_i · G` for some scalar `y_i`, and
2. `norm_big_c_i = λ_i · x_i · H(pk, app_id) + λ_i · y_i · A`, where `x_i` is consistent with the participant's committed public key share from DKG.

This is a standard "proof of correct ElGamal encryption" (a Chaum–Pedersen DLEQ proof). The coordinator must verify all such proofs before aggregating contributions, mirroring the verification already performed in `do_keyshare` for DKG contributions. [5](#0-4) 

---

### Proof of Concept

Attacker is participant `P_m` with valid key share `x_m`. Instead of computing the correct `(norm_big_y_m, norm_big_c_m)`, they send `(G, G)` (the generator point for both fields).

The coordinator aggregates:
```
Y = Σ_{j≠m} λ_j · y_j · G  +  G
C = Σ_{j≠m} λ_j · (x_j · H + y_j · A)  +  G
```

The TEE app decrypts:
```
s' = C − a·Y
   = [msk · H(pk, app_id) − λ_m · x_m · H(pk, app_id) − λ_m · y_m · A]
     + G − a·G
   = (msk − λ_m · x_m) · H(pk, app_id) + (1 − a) · G − λ_m · y_m · A
```

This is not `msk · H(pk, app_id)`. The TEE app receives a permanently wrong confidential key with no indication of failure, since the CKD protocol performs no output consistency check. [6](#0-5)

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

**File:** src/dkg.rs (L443-477)
```rust
    // Start Round 4
    let wait_round_3 = chan.next_waitpoint();
    // Step 4.2 4.3 and 4.4
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
