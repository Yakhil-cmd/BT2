### Title
Malicious CKD Participant Can Corrupt Coordinator Output Without Detection — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `do_ckd_coordinator` function in the Confidential Key Derivation (CKD) protocol blindly aggregates `(norm_big_y, norm_big_c)` shares received from participants without any cryptographic verification that those shares were honestly computed. This is the direct analog of the Pendle PT oracle bug: just as `OraclePendlePT` assumes a guaranteed 1:1 redemption without validating the actual execution path, `do_ckd_coordinator` assumes every participant's contribution is correctly formed without validating it.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's `CKDOutput` and sums them:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

Each honest participant is supposed to compute:

- `big_y = y_i · G` (random blinding point)
- `big_s = x_i · H(pk ‖ app_id)` (secret share contribution)
- `big_c = big_s + y_i · app_pk`
- `norm_big_y = λ_i · big_y`, `norm_big_c = λ_i · big_c` [2](#0-1) 

The coordinator then sums all `norm_big_y` and `norm_big_c` to produce the final `CKDOutput`. The TEE later calls `unmask(app_sk)` to recover `msk · H(pk ‖ app_id)`.

**No proof of correct formation is attached to the participant's message.** A malicious participant can send any arbitrary `(norm_big_y', norm_big_c')` pair. The coordinator has no way to detect this because:

1. There is no DLOG equality proof showing that `norm_big_c - λ_i · big_s_i` and `norm_big_y` share the same discrete log (under `app_pk` and `G` respectively).
2. The codebase already contains a `dlogeq` proof primitive (`src/crypto/proofs/dlogeq.rs`) that is unused in this protocol. [3](#0-2) 

The `do_ckd_participant` function sends the share with no accompanying proof:

```rust
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
``` [4](#0-3) 

---

### Impact Explanation

A malicious participant sends `(norm_big_y', norm_big_c')` where `norm_big_c' = norm_big_c_honest + Δ` for an arbitrary group element `Δ`. The coordinator outputs `C_final = C_correct + Δ`. The TEE then unmasks to `msk · H(pk ‖ app_id) + Δ`, which is an incorrect confidential key. The derived secret is silently wrong — the TEE has no way to detect the corruption.

This maps to: **High — Corruption of CKD outputs so honest parties accept incorrect cryptographic outputs.**

Since the CKD protocol requires all `n` participants to contribute (Lagrange interpolation over the full set), a **single** malicious participant is sufficient to corrupt the output for every honest party and the coordinator.

---

### Likelihood Explanation

Any participant in the CKD protocol is an attacker-controlled entry point. The attack requires no special privilege — just participation in the protocol. The malicious participant simply deviates from the protocol by sending an arbitrary `(norm_big_y, norm_big_c)` instead of the honestly computed value. There is no detection mechanism.

---

### Recommendation

Attach a DLOG equality proof to each participant's `(norm_big_y, norm_big_c)` message, proving that the discrete log of `norm_big_c - λ_i · big_s_i` under `app_pk` equals the discrete log of `norm_big_y` under `G`. The `dlogeq::prove_with_nonce` / `dlogeq::verify` primitives already exist in `src/crypto/proofs/dlogeq.rs` and should be used here. The coordinator must verify each participant's proof before aggregating their contribution. [5](#0-4) 

---

### Proof of Concept

1. Honest participants compute `(norm_big_y_i, norm_big_c_i)` correctly.
2. Malicious participant `j` instead sends `(norm_big_y_j, norm_big_c_j + Δ)` for any non-identity `Δ ∈ G1`.
3. Coordinator sums all contributions: `C_final = C_correct + Δ`, `Y_final = Y_correct`.
4. TEE calls `unmask(app_sk)`: computes `C_final - app_sk · Y_final = msk · H(pk ‖ app_id) + Δ`.
5. The derived confidential key is `msk · H(pk ‖ app_id) + Δ` — silently wrong, with no error returned.

The coordinator accepts the corrupted output because `do_ckd_coordinator` performs no per-participant validation before aggregation. [6](#0-5)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-32)
```rust
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
```

**File:** src/confidential_key_derivation/protocol.rs (L35-58)
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
}
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

**File:** src/crypto/proofs/dlogeq.rs (L105-134)
```rust
pub fn prove_with_nonce<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    witness: Witness<C>,
    k: Scalar<C>,
) -> Result<Proof<C>, ProtocolError>
where
    Element<C>: ConstantTimeEq,
{
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }

    transcript.message(NEAR_DLOGEQ_STATEMENT_LABEL, &statement.encode()?);

    let (big_k_0, big_k_1) = statement.phi(&k);

    // This will never raise error as k is not zero and generator1 is not the identity
    let enc = encode_two_points::<C>(&big_k_0, &big_k_1)?;

    transcript.message(NEAR_DLOGEQ_COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(NEAR_DLOGEQ_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    let s = k + e * witness.x.0;
    Ok(Proof {
        e: SerializableScalar::<C>(e),
        s: SerializableScalar::<C>(s),
    })
}
```

**File:** src/crypto/proofs/dlogeq.rs (L139-163)
```rust
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
```
