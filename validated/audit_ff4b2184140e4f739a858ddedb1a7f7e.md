### Title
Malicious Participant Can Silently Corrupt CKD Output via Unverified Contribution — (`File: src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator aggregates `(big_y, big_c)` group-element contributions from participants with no proof of correctness. A single malicious participant can substitute arbitrary group elements, silently corrupting the derived confidential key. No error is raised; honest parties accept the wrong output.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's `(norm_big_y, norm_big_c)` pair and unconditionally adds them to the running aggregate: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

The values that each honest participant is supposed to send are computed in `compute_signature_share`: [2](#0-1) 

- `big_y = y * G` (random nonce)
- `big_c = x_i * H(pk ‖ app_id) + y * app_pk` (ElGamal encryption of the secret share)
- `norm_big_y = λ_i * big_y`, `norm_big_c = λ_i * big_c`

There is **no zero-knowledge proof** that the received pair is correctly formed — i.e., that `big_c` encodes the participant's actual secret share under the same nonce `y` used in `big_y`. A malicious participant running `do_ckd_participant` can send any two group elements in place of the correct values: [3](#0-2) 

The coordinator has no mechanism to detect the substitution. Contrast this with the OT-based ECDSA signing protocol, which performs a final `sig.verify()` check before accepting the output: [4](#0-3) 

No equivalent correctness check exists in the CKD coordinator path.

---

### Impact Explanation

The final CKD output `(big_y_total, big_c_total)` is the sum of all participants' contributions. When a malicious participant substitutes `(Y_attack, C_attack)` for their correct share, the coordinator outputs:

```
big_y_total  = Σ_{j≠M}(λ_j · y_j · G) + Y_attack
big_c_total  = msk · H(pk‖app_id) + Σ_{j≠M}(λ_j · y_j) · app_pk + C_attack
```

After `unmask(app_sk)`:

```
big_c_total − app_sk · big_y_total
  = msk · H(pk‖app_id) + C_attack − app_sk · Y_attack   ← wrong
```

The coordinator emits this corrupted `CKDOutput` with no error. Honest parties (including the application calling `unmask`) accept it as valid, receiving an incorrect confidential derived key. This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

---

### Likelihood Explanation

Any single participant in a CKD session can trigger this. The attacker needs only to be a legitimate protocol participant (no leaked keys, no external compromise required). The malicious participant simply deviates from the protocol in `do_ckd_participant` by sending crafted group elements instead of the correctly computed ones. The attack is unconditionally reachable with one malicious party.

---

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation — specifically a proof that:

1. `big_y = y · G` for a known scalar `y`, and
2. `big_c = x_i · H(pk ‖ app_id) + y · app_pk` for the same `y` and the participant's committed secret share `x_i`.

A Chaum-Pedersen discrete-log equality proof (already used elsewhere in the codebase via the Maurer/Fiat-Shamir framework in `src/crypto/proofs/`) is the natural fit. The coordinator must verify all proofs before aggregating contributions, analogous to how `validate_received_share` and `verify_proof_of_knowledge` gate aggregation in the DKG protocol: [5](#0-4) 

---

### Proof of Concept

1. Honest participants P1, P2 and malicious participant M run `ckd()` with a legitimate coordinator.
2. P1 and P2 call `do_ckd_participant` and send correctly computed `(norm_big_y, norm_big_c)` to the coordinator.
3. M calls `do_ckd_participant` but sends `(identity, identity)` (or any arbitrary group elements) instead of the correct values.
4. The coordinator in `do_ckd_coordinator` receives M's values and adds them without verification:
   ```
   norm_big_y += identity   // M's contribution silently dropped
   norm_big_c += identity
   ```
5. The coordinator emits a `CKDOutput` that is missing M's secret-share contribution.
6. The application calls `ckd_output.unmask(app_sk)` and receives a key that differs from `msk · H(pk ‖ app_id)`.
7. No `ProtocolError` is returned at any step; the corruption is entirely silent. [6](#0-5)

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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L129-133)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
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
