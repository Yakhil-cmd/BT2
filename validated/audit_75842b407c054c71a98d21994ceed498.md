### Title
Malicious CKD Participant Can Corrupt the Derived Confidential Key by Sending Arbitrary Share Values — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

In the Confidential Key Derivation (CKD) protocol, the coordinator aggregates `(norm_big_y, norm_big_c)` contributions from every participant with no cryptographic proof that each contribution is correctly formed. Any single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` and the application to derive an incorrect confidential key. This is a direct analog to the external report's pattern: a restricted-but-malicious actor supplies arbitrary values during a protocol operation, bypassing all validation, and corrupts the protocol output.

---

### Finding Description

**Root cause — no proof of knowledge for CKD share contributions**

`do_ckd_coordinator` in `src/confidential_key_derivation/protocol.rs` (lines 50–55) collects one `CKDOutput` from every other participant and unconditionally adds the received elements together:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each honest participant is supposed to compute and send:

```
norm_big_y = λᵢ · yᵢ · G
norm_big_c = λᵢ · (xᵢ · H(pk ‖ app_id) + yᵢ · app_pk)
```

where `xᵢ` is the participant's private signing share and `yᵢ` is a fresh random scalar. The coordinator then forms the final masked output `(big_Y, big_C)` and the application unmasks it with `app_sk` to recover `msk · H(pk ‖ app_id)`.

There is **no zero-knowledge proof, commitment, or any other check** that the received `(norm_big_y, norm_big_c)` pair is correctly formed. The sender identity is discarded (`_`) and the values are added blindly. [2](#0-1) 

Compare this with the DKG protocol, which verifies a Schnorr proof of knowledge for every participant's polynomial commitment before accepting any share: [3](#0-2) 

and validates every received secret share against the committed polynomial: [4](#0-3) 

The CKD protocol has no equivalent safeguard.

**Attacker-controlled entry path**

A malicious participant calls `ckd(...)` with valid initialization parameters (passing all `InitializationError` checks at lines 76–101), then — instead of running `compute_signature_share` honestly — sends arbitrary `(norm_big_y', norm_big_c')` to the coordinator via `chan.send_private(waitpoint, coordinator, &(norm_big_y', norm_big_c'))`. [5](#0-4) 

The coordinator has no way to distinguish this from an honest contribution.

**Exploit flow**

1. All `N` participants initialize `ckd(...)` with the same public parameters.
2. The malicious participant (non-coordinator) computes `compute_signature_share` to obtain `(norm_big_y, norm_big_c)` but instead sends `(norm_big_y + Δ_Y, norm_big_c + Δ_C)` for attacker-chosen group elements `Δ_Y`, `Δ_C`.
3. The coordinator sums all contributions and produces `CKDOutput = (big_Y + Δ_Y, big_C + Δ_C)`.
4. The application unmasks: `(big_C + Δ_C) − app_sk · (big_Y + Δ_Y) = msk · H(pk ‖ app_id) + Δ_C − app_sk · Δ_Y`.
5. Unless `Δ_C = app_sk · Δ_Y` (which requires knowing `app_sk`), the derived confidential key is wrong. Sending `(0, 0)` is the simplest case: the output is `(msk − λ_malicious · x_malicious) · H(pk ‖ app_id)`.

The attack requires no privileged access, no leaked keys, and no cryptographic break — only participation in the protocol.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

A single malicious participant permanently corrupts the `CKDOutput` for that session. The coordinator and the application have no way to detect the corruption: the output is a valid group element, just the wrong one. Every downstream consumer of the derived confidential key (e.g., a client whose key was supposed to be derived) receives an incorrect key. Re-running the protocol with the same inputs will produce the same corrupted result as long as the malicious participant is present.

This matches the allowed High impact: *"Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs."*

---

### Likelihood Explanation

Any participant in any CKD session can trigger this. No special position (e.g., coordinator role) is required. The malicious participant only needs to be included in the `participants` list, which is a normal precondition for running the protocol. The attack is a single-message deviation from the honest protocol and is undetectable without the missing proof.

---

### Recommendation

Add a zero-knowledge proof of correct formation for each participant's `(norm_big_y, norm_big_c)` contribution before the coordinator aggregates them. Concretely, each participant should prove knowledge of `(xᵢ, yᵢ)` such that:

- `norm_big_y = λᵢ · yᵢ · G`
- `norm_big_c = λᵢ · xᵢ · H(pk ‖ app_id) + λᵢ · yᵢ · app_pk`

A standard `dlog`-equality proof (already used elsewhere in the codebase, e.g., in triple generation) can prove that the discrete-log of `norm_big_y` with respect to `G` equals the discrete-log of `(norm_big_c − λᵢ · xᵢ · H(pk ‖ app_id))` with respect to `app_pk`. The coordinator must verify this proof before adding the contribution.

---

### Proof of Concept

```rust
// Malicious participant: instead of calling compute_signature_share honestly,
// send (identity, identity) to zero out the contribution.
fn do_ckd_participant_malicious(
    mut chan: SharedChannel,
    coordinator: Participant,
) -> Result<CKDOutputOption, ProtocolError> {
    let waitpoint = chan.next_waitpoint();
    // Send the group identity for both elements — no proof required.
    let zero_y = ElementG1::identity();
    let zero_c = ElementG1::identity();
    chan.send_private(waitpoint, coordinator, &(zero_y, zero_c))?;
    Ok(None)
}
// Result: coordinator outputs CKDOutput where big_C is missing the malicious
// participant's share contribution. Application unmasks to
// (msk - λ_malicious * x_malicious) * H(pk || app_id) — wrong key, silently accepted.
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

**File:** src/dkg.rs (L520-527)
```rust
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        // Step 5.3
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
```
