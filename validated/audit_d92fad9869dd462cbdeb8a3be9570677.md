### Title
Coordinator Accepts Unverified CKD Shares and Produces Output Unconditionally - (File: src/confidential_key_derivation/protocol.rs)

### Summary
`do_ckd_coordinator` aggregates participant-supplied ElGamal share components `(big_y, big_c)` into the final `CKDOutput` without any validity check on the received values. A single malicious participant can send arbitrary group elements; the coordinator incorporates them unconditionally and returns a corrupted confidential derived key to all honest parties.

### Finding Description
In `do_ckd_coordinator`, the coordinator collects each participant's `CKDOutput` via `recv_from_others` and blindly adds the components together:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [1](#0-0) 

Each participant is supposed to send `(λ_i · y_i · G₁, λ_i · (x_i · H(pk, app_id) + y_i · A))` — an ElGamal share of their secret contribution. The correctness of the final ciphertext depends on every participant sending a well-formed share. No zero-knowledge proof of correct share formation (e.g., a Chaum-Pedersen DLEQ proof showing the same `y_i` was used in both components) is attached by the sender:

```rust
fn do_ckd_participant(...) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
    Ok(None)
}
``` [2](#0-1) 

And no verification is performed on the coordinator side before the values are summed and returned. [3](#0-2) 

Contrast this with the DKG protocol, which enforces proof-of-knowledge verification, commitment-hash binding, and per-share Feldman verification before accepting any participant contribution: [4](#0-3) 

The CKD protocol has no equivalent safeguard.

### Impact Explanation
A malicious participant sends `(0, 0)` or any arbitrary `(ElementG1, ElementG1)` pair. The coordinator adds these into the running sum, producing a `CKDOutput` whose `big_c` component is not a valid ElGamal encryption of `msk · H(pk, app_id)`. When the application owner calls `unmask(app_sk)`, the result is a random group element unrelated to the intended confidential derived key. All honest parties accept this corrupted output as legitimate because the protocol returns `Ok(Some(ckd_output))` unconditionally.

This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs**.

### Likelihood Explanation
Any single participant in the CKD session can trigger this. No special privilege, leaked key, or cryptographic break is required — only the ability to send a malformed message during the protocol's single communication round. The attacker-controlled entry point is `do_ckd_participant` (or any code that injects a message at the coordinator's `recv_from_others` waitpoint).

### Recommendation
Require each participant to attach a DLEQ (Chaum-Pedersen) zero-knowledge proof demonstrating that the discrete-log relationship between `big_y = y·G₁` and the blinding term `y·A` in `big_c` is consistent. The coordinator must verify each proof before adding the share into the accumulator. Only if all proofs verify should the coordinator proceed to form and return `CKDOutput`.

### Proof of Concept
1. Honest participants run `compute_signature_share` and send correct `(norm_big_y, norm_big_c)`.
2. Malicious participant `P_m` instead sends `CKDOutput::new(ElementG1::identity(), ElementG1::identity())` (or any arbitrary pair).
3. `do_ckd_coordinator` adds `(0, 0)` into the accumulator without complaint.
4. The returned `CKDOutput` satisfies `big_c ≠ msk·H(pk,app_id) + (Σ λ_i·y_i)·A`.
5. `ckd_output.unmask(app_sk)` yields a wrong group element; the confidential derived key is permanently corrupted for this session. [5](#0-4)

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

**File:** src/dkg.rs (L446-476)
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
```
