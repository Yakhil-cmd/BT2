### Title
Missing Validation of Participant Contributions in CKD Coordinator Allows Malicious Participant to Corrupt Derived Confidential Key - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `do_ckd_coordinator` function in the Confidential Key Derivation (CKD) protocol blindly accumulates `CKDOutput` values received from all participants without any proof of correct computation. A single malicious participant can send arbitrary `big_y` and `big_c` values, causing the coordinator to produce a corrupted `CKDOutput`. Honest parties accept this corrupted output, and the TEE derives a wrong or unusable confidential key.

### Finding Description

In `src/confidential_key_derivation/protocol.rs`, the coordinator function `do_ckd_coordinator` (lines 35–58) receives each participant's `(norm_big_y, norm_big_c)` pair and unconditionally adds them into the running sum:

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
- `big_y = y_i * G` (random blinding factor)
- `big_c = x_i * H(pk, app_id) + y_i * app_pk` (ElGamal encryption of their key share)

and send the Lagrange-weighted pair `(λᵢ * big_y, λᵢ * big_c)` to the coordinator. [2](#0-1) 

No zero-knowledge proof or consistency check accompanies these values. The coordinator has no way to verify that a received `big_c` was formed using the participant's actual private share `x_i` and a `y_i` consistent with the submitted `big_y`. The `recv_from_others` call simply deserializes and returns whatever group elements were sent. [3](#0-2) 

This is structurally identical to the reported `minOut = 0` pattern: just as the swap accepted any output amount without a lower-bound check, the CKD coordinator accepts any participant contribution without a correctness check.

### Impact Explanation

The final `CKDOutput` is an ElGamal ciphertext `(Σ λᵢ·Y_i, Σ λᵢ·C_i)`. The TEE decrypts it as:

```
confidential_key = big_c_total - app_sk * big_y_total
                 = msk * H(pk, app_id)   (when all contributions are honest)
```

If one malicious participant injects an arbitrary additive offset `(δ_Y, δ_C)`, the TEE instead derives:

```
confidential_key = msk * H(pk, app_id) + δ_C - app_sk * δ_Y
```

This is a wrong key. The coordinator and all honest parties accept the corrupted `CKDOutput` with no error, satisfying the **High** impact criterion: *Corruption of CKD outputs so honest parties accept unusable cryptographic outputs*.

### Likelihood Explanation

Any single participant in the CKD session is a sufficient attacker. The protocol requires **all** participants to contribute (the coordinator waits for `recv_from_others` to complete before producing output). There is no threshold redundancy that could absorb one bad contribution. The attacker needs only to be a legitimate participant and send a malformed `CKDOutput`; no cryptographic break or privileged access is required.

### Recommendation

Each participant should accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation. Concretely, a participant must prove in zero knowledge:

1. They know `y_i` such that `big_y = y_i * G`.
2. They know `x_i` such that `x_i * G2 = vk_share_i` (their public key share on G2).
3. `big_c = x_i * H(pk, app_id) + y_i * app_pk`.

A suitable construction is a Sigma protocol (e.g., a DLEQ-style proof) over the BLS12-381 G1 curve, similar to the `dlogeq` proof already present in `src/crypto/proofs/dlogeq.rs`. [4](#0-3) 

The coordinator must verify this proof before adding the contribution to the running sum, and abort with `ProtocolError::MaliciousParticipant` on failure.

### Proof of Concept

**Setup:** 3 participants run CKD. Participant 3 is malicious.

**Honest flow:** Participants 1 and 2 call `compute_signature_share` and send correct `(norm_big_y, norm_big_c)` to the coordinator.

**Attack:** Participant 3 skips `compute_signature_share` entirely and instead sends `(ElementG1::identity(), ElementG1::generator())` — arbitrary group elements — as its `CKDOutput`.

**Result:** The coordinator at line 53–54 adds these values unconditionally:

```rust
norm_big_y += participant_output.big_y();  // += identity  (no-op on Y)
norm_big_c += participant_output.big_c();  // += G  (corrupts C)
``` [5](#0-4) 

The coordinator returns a `CKDOutput` where `big_c` is offset by `G`. The TEE decrypts this and obtains `msk * H(pk, app_id) + G`, which is not the intended confidential key. No error is raised anywhere in the protocol. The honest parties have accepted a corrupted CKD output.

### Citations

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
