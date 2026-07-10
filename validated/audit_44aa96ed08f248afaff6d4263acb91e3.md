### Title
Missing Proof of Knowledge for CKD Participant Shares Allows Malicious Participant to Corrupt CKD Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `do_ckd_coordinator` function accepts `(norm_big_y, norm_big_c)` from each participant and sums them without any cryptographic proof that the values are correctly formed. Analogous to the `minAmount = 0` sandwich-attack root cause — where any output amount is silently accepted — this function accepts any arbitrary group elements from participants with no minimum validity constraint. A single malicious participant can inject arbitrary BLS12-381 G1 elements, causing the coordinator to compute and accept a permanently corrupted CKD output.

### Finding Description
In `do_ckd_coordinator` (lines 50–55 of `src/confidential_key_derivation/protocol.rs`), the coordinator receives a `CKDOutput` pair from each participant and unconditionally accumulates them:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant is supposed to compute in `compute_signature_share` (lines 148–181):
- `norm_big_y = λi · yi · G` — Lagrange-weighted ElGamal nonce commitment
- `norm_big_c = λi · (xi · H(pk, app_id) + yi · app_pk)` — Lagrange-weighted ElGamal ciphertext share

The coordinator sums these to reconstruct an ElGamal encryption of `msk · H(pk, app_id)` under `app_pk`. However, **no DLOGEQ proof or any other cryptographic proof** is sent alongside the share to verify that:
1. The participant used their actual private share `xi` (not an arbitrary scalar).
2. The same `y` was used in both `big_y = y · G` and the `y · app_pk` term inside `big_c`.

The `CKDOutput` type carries only two raw group elements with no attached proof. The coordinator has no mechanism to distinguish a correctly formed share from an arbitrary pair of points. This is the direct analog of `minAmount = 0`: the protocol imposes no lower bound on the validity of received values. [1](#0-0) [2](#0-1) 

### Impact Explanation
The CKD output `(big_y, big_c)` is an ElGamal encryption of `msk · H(pk, app_id)` under `app_pk`. When a malicious participant injects arbitrary values, the coordinator computes and accepts an incorrect encryption. When the application later calls `ckd_output.unmask(app_sk)` it recovers a wrong value instead of `msk · H(pk, app_id)`. The protocol collects shares from **all** participants (not a threshold subset), so there is no redundancy or error-correction: a single corrupted share permanently corrupts the CKD output. Honest parties have no way to detect the manipulation.

This matches: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.** [3](#0-2) 

### Likelihood Explanation
Any single registered participant can trigger this. No special privilege is required beyond being a participant in the CKD session. The attacker does not need to break any cryptographic primitive — they simply send a malformed `(big_y, big_c)` pair (e.g., identity elements, random points, or crafted values). Because the coordinator sums all `n` shares unconditionally, one bad share is sufficient.

### Recommendation
Attach a DLOGEQ proof to each participant's share proving that the same scalar `y` was used in both `big_y = y · G` and the `y · app_pk` component of `big_c`, and that `big_c − y · app_pk` equals the participant's committed public BLS share `xi · H(pk, app_id)`. The existing `dlogeq` proof infrastructure in `src/crypto/proofs/dlogeq.rs` can be reused directly for this purpose. The coordinator must verify each proof before accumulating the share. [4](#0-3) 

### Proof of Concept
1. Honest participants P1 (coordinator), P2, P3 initiate the CKD protocol.
2. Malicious P2 sends `(ElementG1::identity(), ElementG1::identity())` instead of their correct `(norm_big_y, norm_big_c)`.
3. The coordinator at lines 53–54 adds these identity elements to the running sum — silently dropping P2's legitimate Lagrange-weighted contribution.
4. The coordinator outputs `CKDOutput::new(norm_big_y, norm_big_c)` where both components are missing P2's share, producing an encryption of a value other than `msk · H(pk, app_id)`.
5. The application calls `ckd_output.unmask(app_sk)` and recovers an incorrect confidential key.
6. No error is raised; honest parties accept the corrupted output as valid. [5](#0-4)

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

**File:** src/crypto/proofs/dlogeq.rs (L136-164)
```rust
/// Verify that a proof attesting to the validity of some statement.
///
/// We use a transcript in order to verify the Fiat-Shamir transformation.
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> Result<bool, ProtocolError>
where
    Element<C>: ConstantTimeEq,
{
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }

    transcript.message(NEAR_DLOGEQ_STATEMENT_LABEL, &statement.encode()?);

    let (phi0, phi1) = statement.phi(&proof.s.0);
    let big_k0 = phi0 - *statement.public0 * proof.e.0;
    let big_k1 = phi1 - *statement.public1 * proof.e.0;

    let enc = encode_two_points::<C>(&big_k0, &big_k1)?;

    transcript.message(NEAR_DLOGEQ_COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(NEAR_DLOGEQ_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    Ok(e == proof.e.0)
}
```
