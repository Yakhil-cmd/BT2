### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary

In the CKD protocol, the coordinator receives `(norm_big_y, norm_big_c)` shares from every participant and accumulates them with no cryptographic validation. There is no zero-knowledge proof or consistency check that each participant's contribution was computed from their actual key share. A single malicious participant can send arbitrary group elements, silently corrupting the final `CKDOutput` so the app derives a wrong confidential key.

### Finding Description

`do_ckd_coordinator` in `src/confidential_key_derivation/protocol.rs` accumulates participant shares unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

The correct per-participant contribution is computed in `compute_signature_share` as:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
``` [2](#0-1) 

The coordinator has no way to verify that the received `(norm_big_y_i, norm_big_c_i)` satisfies this relation. A malicious participant simply sends arbitrary `ElementG1` values instead. Because the protocol requires **all** participants to contribute (no threshold parameter exists in `ckd()`), a single bad actor is sufficient: [3](#0-2) 

The participant path (`do_ckd_participant`) sends its share privately to the coordinator with no commitment or proof: [4](#0-3) 

Contrast this with the DKG protocol, which enforces proof-of-knowledge verification and commitment-hash binding for every participant contribution before accepting any share: [5](#0-4) 

No equivalent protection exists in the CKD path.

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The coordinator outputs `CKDOutput { Y', C' }` where `Y' = Y + δ_Y` and `C' = C + δ_C` for attacker-chosen `δ_Y, δ_C`. The app unmasks as `C' − app_sk · Y' = msk · H(pk ‖ app_id) + δ_C − app_sk · δ_Y`, which is wrong for any `(δ_Y, δ_C)` not satisfying `δ_C = app_sk · δ_Y`. Since the attacker does not know `app_sk`, they cannot produce a valid forgery, but they can trivially produce an unusable output, permanently denying the app the correct derived key for that invocation.

### Likelihood Explanation

**Medium.** Any participant in the CKD session can mount this attack without any privileged access. The attacker only needs to be a registered participant and deviate from the protocol in the single message they send to the coordinator. No coordination with other parties is required.

### Recommendation

Each participant should accompany their `(norm_big_y_i, norm_big_c_i)` with a zero-knowledge proof of correct computation — specifically a proof that:
1. `norm_big_y_i` is a scalar multiple of `G` consistent with the Lagrange weight `λ_i`.
2. `norm_big_c_i` was formed using the same scalar and the participant's committed public key share (i.e., a Chaum–Pedersen or sigma-protocol proof over the two bases `G` and `app_pk`).

The coordinator must verify all proofs before accumulating any contribution, mirroring the proof-of-knowledge checks already present in `do_keyshare`.

### Proof of Concept

1. Run `ckd()` with participants `[P1, P2, P3]`; `P2` is malicious.
2. `P2` calls `compute_signature_share` to obtain its correct `(norm_big_y_2, norm_big_c_2)` but discards them.
3. `P2` instead sends `(ElementG1::generator(), ElementG1::generator())` (or any arbitrary non-zero elements) to the coordinator via `chan.send_private`.
4. The coordinator's loop at lines 50–55 adds these unchecked values into `norm_big_y` and `norm_big_c`.
5. The resulting `CKDOutput` is `(Y + G, C + G)`.
6. The app computes `(C + G) − app_sk · (Y + G) = msk · H(pk ‖ app_id) + G(1 − app_sk)`, which is not the correct confidential key.
7. The honest coordinator and app have no way to detect the corruption; the protocol returns `Ok(Some(ckd_output))` with the corrupted value. [6](#0-5)

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

**File:** src/confidential_key_derivation/protocol.rs (L165-181)
```rust
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
