### Title
Malicious Participant Can Corrupt CKD Output by Sending Arbitrary Shares Without Proof of Correctness — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

In the Confidential Key Derivation (CKD) protocol, the coordinator aggregates elliptic-curve share contributions from every participant with no cryptographic verification of their correctness. A single malicious participant can send arbitrary `(norm_big_y, norm_big_c)` values, causing the coordinator to produce an incorrect derived confidential key that is unusable by the TEE application.

---

### Finding Description

`do_ckd_coordinator` (lines 35–57) receives a `CKDOutput` from every other participant and unconditionally adds each contribution to its running sum:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

The correct share that participant `i` is supposed to contribute is computed in `compute_signature_share` as:

- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)` [2](#0-1) 

No zero-knowledge proof, commitment, or any other cryptographic check is attached to the message sent by `do_ckd_participant`:

```rust
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
``` [3](#0-2) 

The coordinator has no way to verify that the received group elements are consistent with the sender's public key share or with the claimed blinding factor `y_i`. Any participant can substitute arbitrary curve points and the coordinator will silently incorporate them into the final output.

This contrasts sharply with the DKG layer, where every participant's polynomial commitment is verified against a proof-of-knowledge before any share is accepted: [4](#0-3) 

---

### Impact Explanation

The CKD protocol is the mechanism by which TEE applications receive deterministic secrets derived from the threshold master key without ever reconstructing that key. The final output is:

```
Y = Σ norm_big_y_i
C = Σ norm_big_c_i
confidential_key = C − Y · app_sk
```

If participant `m` sends `(Δ_Y, Δ_C)` instead of its correct contribution, the coordinator computes:

```
Y' = Y_correct + (Δ_Y − norm_big_y_m)
C' = C_correct + (Δ_C − norm_big_c_m)
confidential_key' = confidential_key_correct + (Δ_C − Δ_Y · app_sk) − (norm_big_c_m − norm_big_y_m · app_sk)
```

The derived key is wrong. Sending identity elements `(0, 0)` is sufficient to make the output completely incorrect and unusable. This maps directly to the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

---

### Likelihood Explanation

The CKD protocol aggregates contributions from **all** participants (not merely a threshold subset). Therefore a **single** malicious participant is sufficient to corrupt the output — no collusion is required. Any registered participant in the protocol is a reachable attacker. The attack requires only that the participant deviate from the protocol by sending crafted curve points, which is trivially achievable by any library caller who controls their own process. [5](#0-4) 

---

### Recommendation

Attach a Chaum-Pedersen (or equivalent) zero-knowledge proof to each participant's share message, proving that:

1. `norm_big_y = λ_i · y_i · G` for the same `y_i` used in step 2.
2. `norm_big_c − λ_i · x_i · H(pk ‖ app_id) = y_i · (λ_i · app_pk)`, i.e., the blinding is consistent with the public key share `X_i = x_i · G2` established during DKG.

The coordinator must verify these proofs before adding any contribution to the running sum, analogous to how `verify_proof_of_knowledge` gates share acceptance in the DKG layer. [6](#0-5) 

---

### Proof of Concept

1. Participants `{P_1, …, P_n}` run the CKD protocol. Participant `P_m` is malicious.
2. `P_m` calls `ckd(...)` normally to obtain a valid protocol handle, but in its internal execution deviates by sending `(G1::identity(), G1::identity())` to the coordinator instead of the correctly computed share.
3. The coordinator's `do_ckd_coordinator` receives the identity elements from `P_m` and adds them to the running sum without error.
4. The final `CKDOutput` is `(Y_correct − norm_big_y_m, C_correct − norm_big_c_m)`.
5. The TEE application calls `ckd_output.unmask(app_sk)` and obtains a key that differs from `msk · H(pk ‖ app_id)` by a non-zero offset.
6. All honest parties accept this incorrect output as the derived confidential key, permanently corrupting the CKD result for that `(app_id, app_pk)` invocation. [7](#0-6)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-31)
```rust
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

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

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
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

**File:** src/dkg.rs (L452-460)
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
```
