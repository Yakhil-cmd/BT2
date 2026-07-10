### Title
Missing Integrity Verification of Participant Shares in CKD Coordinator Allows Malicious Participant to Corrupt Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

---

### Summary
The CKD coordinator blindly aggregates `(norm_big_y, norm_big_c)` shares from all participants with no proof of correct formation. A single malicious participant can substitute arbitrary group elements, causing the coordinator to output a permanently corrupted confidential derived key that honest parties will accept as valid.

---

### Finding Description

In `do_ckd_coordinator` the coordinator collects each participant's share and adds them together unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each honest participant is supposed to send:

```
norm_big_y = λᵢ · yᵢ · G₁
norm_big_c = λᵢ · (xᵢ · H(pk ‖ app_id) + yᵢ · app_pk)
```

computed in `compute_signature_share`: [2](#0-1) 

The coordinator has no mechanism to verify that the received `(norm_big_y, norm_big_c)` pair is consistent with the sender's public key share. There is no zero-knowledge proof, no commitment-then-reveal, and no pairing-based consistency check. The DKG protocol, by contrast, enforces proofs of knowledge and commitment hashes before accepting any participant contribution: [3](#0-2) 

The CKD protocol provides no equivalent safeguard.

---

### Impact Explanation

A malicious participant sends arbitrary `(Δ_Y, Δ_C) ∈ G₁ × G₁` in place of their legitimate share. The coordinator computes:

```
Y'  = Y_honest + Δ_Y
C'  = C_honest + Δ_C
```

When the application unmasks the output with `app_sk`:

```
C' − Y' · app_sk  =  msk · H(pk ‖ app_id)  +  Δ_C − Δ_Y · app_sk
```

Unless `Δ_C = Δ_Y · app_sk` (which requires knowing the application's secret key), the result is a uniformly random, incorrect group element. The coordinator returns this as a valid `CKDOutput` and honest parties have no way to detect the corruption.

**Matched impact**: *High — Corruption of CKD outputs so honest parties accept unusable or incorrect cryptographic outputs.* [4](#0-3) 

---

### Likelihood Explanation

Any single participant in the CKD session is a sufficient attacker. The attack requires only that the malicious participant replace their legitimate `compute_signature_share` output with arbitrary G₁ elements before calling `chan.send_private`. No cryptographic break, no key leakage, and no external assumption is needed. The participant role is explicitly part of the library's caller-controlled API surface: [5](#0-4) 

**Likelihood: Medium-High** — any one of the N participants can trigger this undetected.

---

### Recommendation

Add a non-interactive zero-knowledge proof of correct share formation alongside each `(norm_big_y, norm_big_c)` message. Concretely, participant `i` should prove knowledge of `yᵢ` such that:

- `norm_big_y = λᵢ · yᵢ · G₁`  
- `norm_big_c − λᵢ · vk_shareᵢ · H(pk ‖ app_id) = λᵢ · yᵢ · app_pk`

where `vk_shareᵢ` is the participant's public key share (available from the `KeygenOutput`). This is a standard two-statement Schnorr proof (same witness `yᵢ` in both equations) and can be verified by the coordinator before aggregating. The coordinator should reject and abort if any proof fails, identifying the malicious participant.

---

### Proof of Concept

```
Participants: {P1 (honest), P2 (honest), P_mal (malicious)}
Coordinator: P1

1. P_mal computes legitimate (norm_big_y, norm_big_c) via compute_signature_share.
2. P_mal discards the result and instead sends (G₁, G₁) to the coordinator.
3. Coordinator receives honest shares from P1 and P2, and (G₁, G₁) from P_mal.
4. Coordinator sums all three pairs unconditionally (no check at lines 50-55).
5. Coordinator returns CKDOutput { big_y: Y_honest + G₁, big_c: C_honest + G₁ }.
6. Application calls ckd_output.unmask(app_sk):
       result = (C_honest + G₁) − (Y_honest + G₁) · app_sk
              = msk · H(pk ‖ app_id) + G₁ − G₁ · app_sk   ← wrong key
7. Honest parties accept this corrupted output; the derived key is permanently incorrect.
```

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
