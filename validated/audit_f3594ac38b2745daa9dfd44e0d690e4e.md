### Title
Malicious Participant Can Corrupt CKD Output by Sending Unvalidated Elliptic Curve Points — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function in the CKD protocol accumulates `(big_y, big_c)` contributions from all participants without any cryptographic validation. A single malicious participant can send arbitrary elliptic curve points, causing the coordinator to silently output a corrupted `CKDOutput`. The application consuming this output will derive a wrong confidential key and accept it as valid, with no error signal.

### Finding Description

In `src/confidential_key_derivation/protocol.rs`, `do_ckd_coordinator` (lines 50–55) receives a `CKDOutput` from every other participant and unconditionally adds the two group elements together:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

No validation is performed on the received values:

- No check that `big_y` or `big_c` is not the identity element (the group's zero).
- No proof of knowledge (e.g., a Schnorr proof) that the sender knows the discrete log of `big_y`.
- No consistency check between `big_y` and `big_c` relative to the sender's public share or `app_pk`.

Compare this with the DKG protocol (`src/dkg.rs`), which validates every participant contribution with `verify_proof_of_knowledge` (lines 452–460) and `validate_received_share` (lines 520–522) before accumulating anything. The CKD coordinator has no equivalent gate.

The honest computation each participant `i` is supposed to contribute is:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk, app_id) + y_i · app_pk)
```

Because the coordinator performs a plain additive accumulation with no verification, any participant can substitute arbitrary points `(big_y', big_c')` for their legitimate contribution. The resulting `CKDOutput` is:

```
Y_out  = Y_honest + (big_y'  − norm_big_y_malicious)
C_out  = C_honest + (big_c'  − norm_big_c_malicious)
```

When the application calls `ckd_output.unmask(app_sk)`, it computes `C_out − app_sk · Y_out`, which equals `msk · H(pk, app_id)` only when all contributions are honest. With a corrupted contribution the result is a wrong, attacker-influenced group element that the application silently accepts.

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The coordinator returns a `CKDOutput` that is structurally well-formed (two valid group elements) but cryptographically wrong. The caller has no way to distinguish a corrupted output from a correct one: there is no MAC, no proof, and no independent verification step after `do_ckd_coordinator` returns. Every honest party that relies on the derived confidential key will silently operate on a wrong value. This matches the allowed High impact: *"Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs."*

### Likelihood Explanation

Any one of the N participants in a CKD session can trigger this. No privileged access, no leaked key, and no external oracle is required. The attacker only needs to be a legitimate protocol participant — the lowest possible privilege level — and to send crafted bytes in the single message they are already expected to send to the coordinator.

### Recommendation

1. **Require a proof of knowledge for `big_y`**: Each participant should accompany `(norm_big_y, norm_big_c)` with a Schnorr proof that they know the scalar `y_i` such that `norm_big_y = λ_i · y_i · G`. The coordinator must verify this proof before accumulating the contribution.
2. **Reject the identity element**: Before accumulating, check that neither `big_y` nor `big_c` is the group identity; an identity contribution is always malicious.
3. **Consistency check**: Verify that `norm_big_c − norm_big_y · (app_pk / G)` lies on the expected coset, or use a zero-knowledge proof of the linear relation between `big_y` and `big_c`.

The DKG protocol in `src/dkg.rs` already demonstrates the correct pattern: every participant contribution is cryptographically verified before it is accumulated into shared state.

### Proof of Concept

1. Instantiate a CKD session with participants `[P1, P2, P3]` and coordinator `P1`.
2. `P2` (malicious) computes its legitimate `(norm_big_y_2, norm_big_c_2)` but instead sends `(identity, identity)` — the group zero — to the coordinator.
3. The coordinator's loop at lines 50–55 adds the identity to the running sum, effectively dropping `P2`'s honest contribution.
4. The coordinator emits a `CKDOutput` whose `unmask(app_sk)` value equals `(λ_1·x_1 + λ_3·x_3) · H(pk, app_id)` instead of `msk · H(pk, app_id)`.
5. The application receives this output, calls `unmask`, and silently derives a wrong confidential key with no error returned.
6. Alternatively, `P2` can send `(big_y', big_c')` with `big_c' = big_c_legitimate + Δ` for any chosen `Δ`, shifting the derived key by an attacker-controlled offset. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** src/dkg.rs (L519-522)
```rust
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
```
