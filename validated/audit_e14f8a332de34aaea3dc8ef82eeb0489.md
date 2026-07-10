### Title
Malicious Participant Can Send Arbitrary Unvalidated CKD Contribution to Corrupt Confidential Key Derivation Output - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator in `do_ckd_coordinator` accepts each participant's `CKDOutput` contribution and accumulates it into the final result with no zero-knowledge proof or algebraic consistency check. Any participant in the protocol can substitute an arbitrary `(big_y, big_c)` pair, causing the coordinator to produce a corrupted CKD output. The app that unmasks the result will derive a wrong confidential key.

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's `(norm_big_y, norm_big_c)` contribution and adds them together unconditionally: [1](#0-0) 

Each participant is supposed to send:
- `norm_big_y = λᵢ · yᵢ · G`
- `norm_big_c = λᵢ · (xᵢ · H(pk ‖ app_id) + yᵢ · A)`

where `xᵢ` is their private key share, `yᵢ` is a fresh random scalar, and `A` is the app's public key. The coordinator sums all contributions and returns the aggregate `(big_y, big_c)` to the app, which unmasks it as:

```
confidential_key = big_c - app_sk · big_y = msk · H(pk ‖ app_id)
```

However, there is **no proof of correctness** attached to each participant's contribution. The coordinator performs no check that the received `(norm_big_y, norm_big_c)` is consistent with the participant's committed key share or any randomness. A malicious participant can send any arbitrary group elements.

The `compute_signature_share` function that honest participants use is: [2](#0-1) 

A malicious participant simply skips this computation and sends `(big_y', big_c')` of their choosing. The coordinator has no mechanism to detect this.

Compare with the DKG protocol, which does validate received shares against committed polynomials via `validate_received_share` and `verify_proof_of_knowledge`: [3](#0-2) 

No equivalent validation exists in the CKD coordinator path.

### Impact Explanation

A malicious participant sends `big_y' = 0` and `big_c' = δ` (arbitrary). The coordinator computes:

```
big_y_final = Σ(honest) + 0
big_c_final = Σ(honest) + δ
```

The app unmasks:
```
big_c_final - app_sk · big_y_final = msk · H(pk ‖ app_id) + δ
```

The derived confidential key is shifted by an attacker-controlled `δ`. The app receives a deterministically wrong key that it cannot distinguish from a correct one. Alternatively, the attacker can set `big_c' = -Σ(honest_c)` and `big_y' = -Σ(honest_y)` to force the output to the identity element, making the derived key the zero scalar.

This matches: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation

Any single participant in the CKD protocol can execute this attack. The participant list is caller-supplied and can include an adversary. The attack requires only that the malicious participant deviate from the protocol by sending arbitrary bytes in place of their honest contribution — no cryptographic capability is needed. The coordinator has no detection mechanism.

### Recommendation

Require each participant to attach a zero-knowledge proof of correct formation alongside their `(norm_big_y, norm_big_c)` contribution. Specifically, each participant should prove in zero-knowledge that:

1. `norm_big_y = λᵢ · yᵢ · G` for some `yᵢ` (a Schnorr proof of discrete log).
2. `norm_big_c = λᵢ · xᵢ · H(pk ‖ app_id) + λᵢ · yᵢ · A`, consistent with the same `yᵢ` and the participant's committed public key share `Xᵢ = xᵢ · G₂`.

The coordinator must verify all proofs before accumulating contributions, aborting and identifying the malicious participant if any proof fails. This is analogous to how `validate_received_share` and `verify_proof_of_knowledge` protect the DKG round.

### Proof of Concept

1. Run the CKD protocol with 3 participants, one of which is malicious.
2. The malicious participant, instead of calling `compute_signature_share`, sends `(ElementG1::identity(), δ)` for any chosen `δ`.
3. The coordinator at `do_ckd_coordinator` lines 50–55 accumulates this without complaint.
4. The app calls `ckd_output.unmask(app_sk)` and obtains `msk · H(pk ‖ app_id) + δ` instead of `msk · H(pk ‖ app_id)`.
5. The app silently uses the wrong key for all subsequent operations. [4](#0-3)

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

**File:** src/confidential_key_derivation/protocol.rs (L148-181)
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
```

**File:** src/dkg.rs (L259-285)
```rust
fn validate_received_share<C: Ciphersuite>(
    me: Participant,
    from: Participant,
    signing_share_from: &SigningShare<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> Result<(), ProtocolError> {
    let id = me.to_identifier::<C>()?;

    // The verification is exactly the same as the regular SecretShare verification;
    // however the required components are in different places.
    // Build a temporary SecretShare so what we can call verify().
    let secret_share = SecretShare::new(id, *signing_share_from, commitment.clone());

    // Verify the share. We don't need the result.
    // Identify the culprit if an InvalidSecretShare error is returned.
    secret_share.verify().map_err(|e| {
        if let Error::InvalidSecretShare { .. } = e {
            ProtocolError::InvalidSecretShare(from)
        } else {
            ProtocolError::AssertionFailed(format!(
                "could not
            extract the verification key matching the secret
            share sent by {from:?}"
            ))
        }
    })?;
    Ok(())
```
