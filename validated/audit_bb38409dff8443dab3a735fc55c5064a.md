### Title
Missing Proof-of-Correct-Computation for Participant Shares in CKD Protocol Allows Malicious Participant to Corrupt Confidential Key Derivation Output — (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The CKD coordinator aggregates `(big_y, big_c)` shares received from every participant with no cryptographic proof that each share was honestly computed from the participant's actual secret key share. A single malicious participant can substitute arbitrary group elements, silently corrupting the final `CKDOutput` that honest parties accept as correct — a direct structural analog to the ERC-20 "unchecked return value / fee-on-transfer" class: the code assumes the received value equals the expected value, but never verifies it.

---

### Finding Description

In `do_ckd_coordinator` the coordinator loops over every other participant's message and unconditionally adds the received `big_y` and `big_c` into the running sums:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();   // no proof checked
    norm_big_c += participant_output.big_c();   // no proof checked
}
``` [1](#0-0) 

The honest computation each participant is supposed to perform is:

```
big_y  = y · G
big_c  = x_i · H(pk ‖ app_id) + y · A
norm_* = λ_i · *
``` [2](#0-1) 

There is no zero-knowledge proof, no Pedersen commitment, and no consistency check binding the received `big_c` to the participant's public key share. The coordinator has no mechanism to distinguish a correctly-formed share from an arbitrary group element.

Contrast this with the DKG protocol, which enforces a proof-of-knowledge for every participant's polynomial commitment and validates every received secret share against the committed polynomial before accepting it: [3](#0-2) [4](#0-3) 

The CKD protocol provides no equivalent safeguard.

---

### Impact Explanation

The `unmask` operation recovers the confidential key as:

```
big_c_total − app_sk · big_y_total  =  msk · H(pk ‖ app_id)
```

If a malicious participant substitutes `big_c' = big_c_honest + Δ` for an arbitrary curve point `Δ`, the coordinator computes:

```
(msk · H(pk ‖ app_id) + Δ) − app_sk · big_y_total
```

The resulting confidential key is permanently wrong. Every honest party that relies on the `CKDOutput` (e.g., a TEE decrypting data with the derived key) will silently accept a corrupted value. This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs**.

---

### Likelihood Explanation

The attacker must be one of the `n` participants listed in the `ckd()` call. Because the CKD protocol has no threshold parameter — it requires all `n` participants — any single participant in the set is a sufficient attacker. The attack requires only that the participant deviate from the protocol by sending a crafted group element; no cryptographic break, no key leakage, and no external compromise is needed. The entry path is the standard `Protocol::message()` delivery mechanism already used by every participant. [5](#0-4) 

---

### Recommendation

Add a Sigma-protocol (DLEQ) proof alongside each `(big_y, big_c)` share, binding `big_c` to the participant's known public key share `X_i = x_i · G2` and to `big_y`. Specifically, each participant should prove in zero knowledge:

```
DLEQ( big_y / G  ==  (big_c − X_i · H(pk‖app_id)) / A )
```

The coordinator must verify every proof before adding the share to the running sum, mirroring the proof-of-knowledge verification already present in the DKG protocol. [6](#0-5) 

---

### Proof of Concept

1. Honest participants `p_1 … p_{n-1}` compute and send correct `(norm_big_y_i, norm_big_c_i)`.
2. Malicious participant `p_n` sends `(norm_big_y_n, norm_big_c_n + Δ)` where `Δ` is any non-identity `G1` element.
3. The coordinator executes the loop at lines 50–55 and accumulates `sum_big_c = Σ norm_big_c_i + Δ`.
4. `CKDOutput::new(sum_big_y, sum_big_c)` is returned to the application.
5. The application calls `ckd_output.unmask(app_sk)` and obtains `msk · H(pk‖app_id) + Δ` — a permanently corrupted confidential key — with no error, no warning, and no way for honest parties to detect the manipulation. [7](#0-6)

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

**File:** src/confidential_key_derivation/protocol.rs (L66-116)
```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    let comms = Comms::new();
    let chan = comms.shared_channel();

    let fut = run_ckd_protocol(
        chan,
        coordinator,
        me,
        participants,
        key_pair,
        app_id.into(),
        app_pk,
        rng,
    );
    Ok(make_protocol(comms, fut))
```

**File:** src/confidential_key_derivation/protocol.rs (L159-181)
```rust
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

**File:** src/dkg.rs (L259-285)
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
