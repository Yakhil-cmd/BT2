### Title
Malicious CKD Participant Can Corrupt Confidential Key Derivation Output Without Detection - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator blindly sums participant-supplied group elements `(norm_big_y, norm_big_c)` with no zero-knowledge proof or consistency check. Any single malicious participant can substitute arbitrary curve points, causing the coordinator to assemble and return a structurally valid but cryptographically incorrect `CKDOutput`. The honest coordinator and all downstream callers have no way to detect the corruption.

### Finding Description
In `do_ckd_coordinator` the coordinator collects each participant's share and accumulates it unconditionally:

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

Each participant is supposed to compute:

```
norm_big_y = λ_i · (y_i · G)
norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
``` [2](#0-1) 

There is no proof that `norm_big_y` is a scalar multiple of the generator, no proof that `norm_big_c` encodes the participant's actual signing share, and no proof that the same scalar `y_i` was used in both components. A malicious participant simply sends `(0, 0)` or any other pair of group elements.

Contrast this with the OT-based ECDSA presign protocol, which performs explicit public-commitment consistency checks after accumulating participant values:

```rust
if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
    || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
{
    return Err(ProtocolError::AssertionFailed(...));
}
``` [3](#0-2) 

No equivalent check exists in the CKD coordinator path.

### Impact Explanation
The final `CKDOutput` is `(Y, C)` where the caller unmasks the confidential key as `C − app_sk · Y`. If any participant corrupts their additive contribution, the unmasked result is `msk · H(pk ‖ app_id) + δ` for an attacker-controlled `δ`, producing a wrong confidential derived key. The coordinator returns this corrupted output as `Some(ckd_output)` with no error, so honest callers silently accept an unusable or attacker-biased confidential key. This matches the allowed HIGH impact: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

### Likelihood Explanation
Any single participant in the CKD session is a reachable, unprivileged attacker. No special privilege, leaked key, or external oracle is required. The participant simply deviates from the protocol by sending arbitrary group elements in place of their correct share. Because the coordinator performs no verification, the attack succeeds deterministically on every invocation where the malicious participant is present.

### Recommendation
Each participant should accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation — specifically a proof that:
1. `norm_big_y = λ_i · y_i · G` for some scalar `y_i`, and
2. `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)` using the same `y_i` and the participant's committed signing share `x_i`.

A Chaum–Pedersen-style DLEQ proof over the pair `(norm_big_y, norm_big_c − λ_i · x_i · H(pk ‖ app_id))` with base points `(G, app_pk)` is sufficient. The coordinator must verify all proofs before accumulating values, aborting and identifying the malicious participant on failure — mirroring the pattern already used in `do_keyshare` via `verify_proof_of_knowledge`. [4](#0-3) 

### Proof of Concept
1. A set of `n` participants runs the CKD protocol with a legitimate `app_id` and `app_pk`.
2. One malicious participant, instead of calling `compute_signature_share`, sends `(ElementG1::identity(), ElementG1::identity())` to the coordinator.
3. The coordinator accumulates the identity elements alongside the honest shares and calls `CKDOutput::new(norm_big_y, norm_big_c)`.
4. The resulting `norm_big_y` and `norm_big_c` are each missing the malicious participant's Lagrange-weighted contribution.
5. The caller invokes `ckd_output.unmask(app_sk)` and obtains `(msk − λ_malicious · x_malicious) · H(pk ‖ app_id)` — a value that differs from the correct confidential key and is not equal to any key derivable from the master public key.
6. No error is raised at any point; the coordinator returns `Ok(Some(corrupted_output))`. [5](#0-4)

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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L162-168)
```rust
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
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
