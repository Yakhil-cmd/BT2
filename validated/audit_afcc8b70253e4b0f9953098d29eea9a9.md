### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator blindly aggregates participant-provided `(big_y, big_c)` shares without any cryptographic proof of correctness. A single malicious participant can substitute arbitrary group elements, silently corrupting the derived confidential key that all honest parties accept as valid.

### Finding Description
The external report's vulnerability class is **trusting externally-provided values without verification**: `Pawn.pawn()` accepts `offerAmount` from a backend signature with no on-chain collateral check. The direct analog here is `do_ckd_coordinator` accepting each participant's `CKDOutput` with no cryptographic proof that the values were honestly computed.

In `do_ckd_coordinator`, the coordinator receives every participant's `(norm_big_y, norm_big_c)` and unconditionally adds them to the running aggregate: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

There is no verification that:
1. `norm_big_y_i = λ_i · y_i · G` for a `y_i` the participant actually knows (no discrete-log proof).
2. `norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)` where `x_i` is the participant's real signing share (no proof of correct ElGamal encryption).

The honest computation is performed in `compute_signature_share`: [2](#0-1) 

but a malicious participant is free to ignore that function and send any `(ElementG1, ElementG1)` pair directly to the coordinator via `chan.send_private`.

Contrast this with the DKG protocol, which enforces Schnorr proofs of knowledge and commitment-hash binding before accepting any participant contribution: [3](#0-2) 

No equivalent verification exists in the CKD path.

### Impact Explanation
The final `CKDOutput` is `(big_Y, big_C)` where `big_C - app_sk · big_Y` should equal `msk · H(pk ‖ app_id)`. If participant `P_m` sends `(big_y_m', big_c_m')` instead of the correct values, the coordinator computes:

```
big_C' = correct_C + λ_m · (big_c_m' − big_c_m)
big_Y' = correct_Y + λ_m · (big_y_m' − big_y_m)
```

The decrypted key becomes `msk · H(pk ‖ app_id) + λ_m · ((big_c_m' − big_c_m) − app_sk · (big_y_m' − big_y_m))`, which is an attacker-controlled deviation from the correct value. The coordinator returns this corrupted `CKDOutput` as `Some(ckd_output)` with no final integrity check: [4](#0-3) 

Honest parties have no way to detect the corruption. Any TEE or downstream consumer that uses the derived key will silently operate on an attacker-biased secret, rendering the confidential key derivation output cryptographically unusable or attacker-influenced.

**Matched impact**: *High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.*

### Likelihood Explanation
Any single participant in the CKD session can trigger this. No special privilege, leaked key, or cryptographic break is required — the attacker only needs to be a legitimate protocol participant and substitute their honest `send_private` payload with arbitrary group elements. The attack is one-shot and requires no interaction beyond the normal protocol round. [5](#0-4) 

### Recommendation
Add zero-knowledge proofs to each participant's contribution before the coordinator aggregates it:

1. **Discrete-log proof** (`dlog::prove`) that `norm_big_y_i = λ_i · y_i · G` for a known `y_i` — the same pattern already used in triple generation: [6](#0-5) 

2. **Proof of correct ElGamal encryption** (e.g., a `dlogeq` proof) that `norm_big_c_i` is formed from the participant's committed signing share `x_i` and the same `y_i` used in `norm_big_y_i`.

The coordinator should verify both proofs before adding any contribution to the aggregate, mirroring the DKG's `verify_proof_of_knowledge` + `verify_commitment_hash` pattern.

### Proof of Concept
1. Run a 3-of-3 CKD session with participants `[P1, P2, P3]`.
2. `P3` (malicious) replaces its honest `(norm_big_y, norm_big_c)` with `(ElementG1::identity(), ElementG1::identity())` before calling `chan.send_private`.
3. The coordinator at `do_ckd_coordinator` receives the zeroed contribution and adds it:
   - `big_Y' = λ_1·Y_1 + λ_2·Y_2 + 0`
   - `big_C' = λ_1·C_1 + λ_2·C_2 + 0`
4. The returned `CKDOutput` decrypts to `big_C' − app_sk·big_Y' ≠ msk·H(pk ‖ app_id)`.
5. No error is raised; honest parties accept the corrupted output as the valid derived key.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L27-32)
```rust
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
```

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L56-57)
```rust
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L241-252)
```rust
            let statement0 = dlog::Statement::<C> {
                public: &big_e_i.eval_at_zero()?.value(),
            };
            let witness0 = dlog::Witness::<C> {
                x: e.eval_at_zero()?,
            };
            let my_phi_proof0 = dlog::prove_with_nonce(
                &mut transcript.fork(b"dlog0", &me.bytes()),
                statement0,
                witness0,
                my_phi_proof0_nonces[i],
            )?;
```
