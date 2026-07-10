### Title
Malicious CKD Participant Can Corrupt Confidential Key Derivation Output Without Detection — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly sums participant-supplied `(big_y, big_c)` group elements with no proof that each value was honestly derived from the participant's actual key share. A single malicious participant can substitute arbitrary group elements, silently corrupting the derived confidential key delivered to the TEE. Unlike the DKG protocol — which enforces proof-of-knowledge, commitment-hash binding, and share validation — the CKD protocol performs no analogous checks on participant contributions.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator collects one `CKDOutput` from every other participant and accumulates them unconditionally: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

The honest computation each participant *should* perform is: [2](#0-1) 

```
big_y_i  = λ_i · y_i · G
big_c_i  = λ_i · (x_i · H(pk ‖ app_id) + y_i · A)
```

where `x_i` is the participant's private signing share and `A = app_pk`.

There is **no zero-knowledge proof, no commitment binding, and no share-consistency check** that forces a participant to use their actual `x_i`. The coordinator has no way to distinguish a correctly-formed contribution from an arbitrary pair of group elements.

**Contrast with DKG**, which enforces all three layers of verification before accepting any participant's material: [3](#0-2) 

```rust
verify_proof_of_knowledge(…)?;
verify_commitment_hash(…)?;
// …
validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
```

No equivalent guards exist in the CKD path.

**Attack mechanics.** A malicious participant `i` sends `(R, S)` — arbitrary points — instead of their correct `(big_y_i, big_c_i)`. The coordinator computes:

```
Y_out = Σ_{j≠i} λ_j·y_j·G  +  R
C_out = Σ_{j≠i} λ_j·(x_j·H + y_j·A)  +  S
```

The TEE decrypts:

```
C_out − sk_app · Y_out
  = Σ_{j≠i} λ_j·x_j·H  +  S − sk_app·R
  ≠  x · H(pk ‖ app_id)
```

The derived key is wrong. Because the TEE has no reference value for the correct key, the corruption is **undetectable**.

---

### Impact Explanation

This maps to **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

A single malicious participant (no threshold breach required) can cause every honest party and the TEE to silently accept a corrupted confidential derived key. The TEE cannot distinguish the corrupted output from a legitimate one, so the attack succeeds without triggering any error path.

---

### Likelihood Explanation

The attack requires only that a participant deviate from the protocol by sending two arbitrary group elements. No cryptographic capability, no key material beyond their own share, and no coordination with other parties is needed. Any participant in any CKD session can execute this unilaterally.

---

### Recommendation

Add a non-interactive zero-knowledge proof (e.g., a Chaum–Pedersen proof or a Schnorr-based DLEQ proof) that binds each participant's `(big_y_i, big_c_i)` to their committed public key share. Concretely, each participant should prove:

```
DLEQ( big_y_i / G  ==  big_c_i − x_i·H(pk‖app_id) / A )
```

This is the CKD analogue of the proof-of-knowledge check already present in `verify_proof_of_knowledge` inside `src/dkg.rs`. [4](#0-3) 

---

### Proof of Concept

1. Alice (coordinator), Bob, and Charlie run `ckd(…)` for a shared key and a given `app_id`.
2. Charlie is malicious. Instead of calling `compute_signature_share`, Charlie constructs a `CKDOutput` with `big_y = G1::identity()` and `big_c = G1::identity()` and sends it to Alice.
3. Alice's `do_ckd_coordinator` loop adds the identity elements, effectively dropping Charlie's honest contribution and injecting zeros.
4. The final `CKDOutput` satisfies `C_out − sk_app · Y_out = Σ_{j∈{Alice,Bob}} λ_j·x_j·H ≠ x·H`, because Charlie's Lagrange-weighted share is missing.
5. The TEE decrypts a wrong key with no error. All honest parties believe the protocol succeeded. [5](#0-4) [6](#0-5)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L35-58)
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
}
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

**File:** src/dkg.rs (L172-218)
```rust
fn verify_proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: &mut DomainSeparator,
    threshold: ReconstructionLowerBound,
    participant: Participant,
    old_participants: Option<ParticipantList>,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: Option<&Signature<C>>,
) -> Result<(), ProtocolError> {
    let threshold = threshold.value();
    match proof_of_knowledge {
        // if participant did not send anything but he is actually an old participant
        None => {
            // if basic dkg or participant is old
            if old_participants.is_none_or(|p| p.contains(participant)) {
                return Err(ProtocolError::MaliciousParticipant(participant));
            }
            // since previous line did not abort, then we know participant is new indeed
            // check the commitment length is threshold - 1
            if commitment.coefficients().len() != threshold - 1 {
                return Err(ProtocolError::IncorrectNumberOfCommitments);
            }
            // nothing to verify
            Ok(())
        }
        // now we know the proof is not none
        Some(proof_of_knowledge) => {
            // if participant sent something but he is actually a new participant
            if old_participants.is_some_and(|p| !p.contains(participant)) {
                return Err(ProtocolError::MaliciousParticipant(participant));
            }
            // since the previous did not abort, we know the participant is old or we are dealing with a dkg
            if commitment.coefficients().len() != threshold {
                return Err(ProtocolError::IncorrectNumberOfCommitments);
            }

            // creating an identifier as required by the syntax of verify_proof_of_knowledge of frost_core
            internal_verify_proof_of_knowledge(
                session_id,
                domain_separator,
                participant,
                commitment,
                proof_of_knowledge,
            )
        }
    }
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
