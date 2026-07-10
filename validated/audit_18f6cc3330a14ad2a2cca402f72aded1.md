### Title
Malicious CKD Participant Can Corrupt Coordinator's Derived Key Output Without Detection - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly aggregates `(big_y, big_c)` contributions from all participants with no proof-of-correctness check. A single malicious participant can send arbitrary group elements, corrupting the final `CKDOutput` that the coordinator returns to the TEE, causing it to derive an incorrect confidential key.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `(norm_big_y, norm_big_c)` pair and unconditionally adds them into the aggregate:

```rust
// src/confidential_key_derivation/protocol.rs lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each honest participant `i` is supposed to compute:

- `norm_big_y_i = λ_i · y_i · G`
- `norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

where `x_i` is their private share from DKG and `y_i` is a fresh random blinding scalar. This is done in `compute_signature_share`: [2](#0-1) 

The participant then sends these values privately to the coordinator: [3](#0-2) 

**There is no zero-knowledge proof, commitment, or consistency check** that `norm_big_c_i` was actually computed using the participant's committed DKG private share `x_i` and the correct `app_id`. The coordinator has no way to distinguish a correctly-formed contribution from an arbitrary group element.

Compare this to the DKG protocol, which enforces correctness of every participant's polynomial commitment via `verify_proof_of_knowledge` and `validate_received_share` before accepting any contribution: [4](#0-3) 

The CKD protocol has no equivalent safeguard.

---

### Impact Explanation

The correct aggregate is:

```
big_C = msk · H(pk ‖ app_id) + Y_blind · app_pk
```

The TEE recovers the confidential key as `big_C − app_sk · big_Y = msk · H(pk ‖ app_id)`.

If a malicious participant substitutes an arbitrary `big_c_i'` for their honest contribution, the aggregate `big_C` is shifted by `(big_c_i' − big_c_i)`. The TEE then derives a wrong confidential key with no indication of failure. This is a **corruption of CKD output** — honest parties accept a cryptographically invalid result — matching the allowed High impact: *"Corruption of CKD outputs so honest parties accept unusable cryptographic outputs."*

---

### Likelihood Explanation

Any single participant in the CKD session can mount this attack. It requires no special knowledge, no cryptographic break, and no coordination. The malicious participant simply sends a random or adversarially chosen group element instead of their honest contribution. The coordinator has no mechanism to detect or reject it.

---

### Recommendation

Each participant should accompany their `(norm_big_y_i, norm_big_c_i)` with a zero-knowledge proof of correctness — specifically, a Schnorr-style sigma proof demonstrating that:

1. `norm_big_c_i` was computed using the same discrete-log witness as the participant's DKG verification share (binding `x_i` to the committed public key from keygen).
2. The blinding term `y_i` used in `norm_big_c_i` is consistent with `norm_big_y_i`.

The coordinator must verify all such proofs before aggregating contributions, analogous to how `verify_proof_of_knowledge` is enforced in `do_keyshare` before any commitment is accepted. [5](#0-4) 

---

### Proof of Concept

1. Run a CKD session with participants `[P1, P2, P3]` and coordinator `P1`.
2. `P2` (malicious) intercepts the call to `compute_signature_share` and instead sends `(rand_G1_point, rand_G1_point)` to the coordinator.
3. The coordinator in `do_ckd_coordinator` adds `P2`'s arbitrary values into `norm_big_y` and `norm_big_c` without any check.
4. The resulting `CKDOutput` returned by the coordinator is `(big_Y + delta_Y, big_C + delta_C)` where `delta_Y, delta_C` are the differences introduced by `P2`.
5. The TEE computes `(big_C + delta_C) − app_sk · (big_Y + delta_Y) ≠ msk · H(pk ‖ app_id)`, deriving a wrong confidential key with no error signal. [6](#0-5)

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
