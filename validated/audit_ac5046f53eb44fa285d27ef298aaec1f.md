### Title
Unverified Participant Contributions in CKD Coordinator Allow Malicious Participant to Corrupt Derived Key - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `do_ckd_coordinator` function in `src/confidential_key_derivation/protocol.rs` blindly accumulates `(norm_big_y, norm_big_c)` contributions from all participants without any cryptographic verification that each contribution is correctly computed relative to the participant's public key share. A single malicious participant can send arbitrary group elements, causing the coordinator to derive a corrupted confidential key.

### Finding Description
In `do_ckd_coordinator`, the coordinator receives each participant's `(norm_big_y, norm_big_c)` pair and unconditionally adds them to its running sum:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

Each participant is supposed to compute:
- `Y_i = y_i * G` (random blinding point)
- `C_i = x_i * H(pk, app_id) + y_i * app_pk` (masked secret share contribution)
- Then normalize: `norm_Y_i = lambda_i * Y_i`, `norm_C_i = lambda_i * C_i`

These are computed in `compute_signature_share`: [2](#0-1) 

The coordinator has no way to verify that the received `(norm_big_y, norm_big_c)` satisfies the required relationship `norm_big_c = lambda_i * x_i * H(pk, app_id) + norm_big_y * (app_sk / y_i)` — because `app_sk` and `y_i` are unknown to the coordinator. No zero-knowledge proof, commitment scheme, or consistency check is applied to the received values before accumulation.

By contrast, the robust ECDSA presign protocol applies exponent interpolation consistency checks and a `W == g^w` verification after accumulating participant shares, catching malicious deviations: [3](#0-2) 

No analogous check exists in the CKD protocol.

### Impact Explanation
A malicious participant sends arbitrary `(norm_big_y_evil, norm_big_c_evil)` group elements to the coordinator. The coordinator sums them with honest contributions and produces a `CKDOutput` where:

```
Y_final  = Y_honest_sum + norm_big_y_evil
C_final  = C_honest_sum + norm_big_c_evil
```

When the application calls `unmask(app_sk)` to recover the confidential key via `C_final - app_sk * Y_final`, the result is:

```
msk * H(pk, app_id) + (norm_big_c_evil - app_sk * norm_big_y_evil)
```

The extra term `(norm_big_c_evil - app_sk * norm_big_y_evil)` is an attacker-controlled offset (unknown to the attacker in advance since `app_sk` is secret, but nonzero with overwhelming probability for any non-trivial evil input). The coordinator accepts and returns this corrupted output as the legitimate CKD result. Honest parties relying on this derived key receive an unusable or incorrect secret.

This maps to: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation
Any single malicious participant in the CKD protocol can trigger this. The attacker's entry path is direct: call `ckd(...)` with a malicious implementation that sends crafted `(norm_big_y, norm_big_c)` values instead of the correctly computed ones. No special privilege, leaked key, or external assumption is required — only participation in the protocol. The coordinator has no mechanism to detect the deviation.

### Recommendation
Add a zero-knowledge proof of correct construction for each participant's `(norm_big_y, norm_big_c)` contribution. Specifically, each participant should prove knowledge of `(y_i, x_i)` such that:
- `norm_big_y = lambda_i * y_i * G`
- `norm_big_c = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)`

and that `x_i` is consistent with the participant's public key share (verifiable against the public key package from DKG). A DLEQ proof or a Schnorr-based proof of correct linear combination would suffice. The coordinator should verify all proofs before accumulating contributions, rejecting any participant whose proof fails.

### Proof of Concept
1. Honest participants `P1, P2` and malicious participant `P3` run `ckd(...)`.
2. `P3` overrides its protocol implementation to send `norm_big_y = G` (generator) and `norm_big_c = G` to the coordinator instead of the correctly computed values.
3. The coordinator in `do_ckd_coordinator` receives these values and adds them unconditionally to `norm_big_y` and `norm_big_c`.
4. The final `CKDOutput` is `(Y_honest + G, C_honest + G)`.
5. `unmask(app_sk)` returns `msk * H(pk, app_id) + G - app_sk * G = msk * H(pk, app_id) + (1 - app_sk) * G`, which is not the correct confidential key.
6. The coordinator returns this corrupted value with no error, and honest consumers of the CKD output derive an incorrect secret.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L193-213)
```rust
    // check that the exponent interpolations match what has been received
    for (identifier, verifying_share) in identifiers
        .iter()
        .skip(threshold + 1)
        .zip(verifying_shares.iter().skip(threshold + 1))
    {
        // Step 3.2
        // exponent interpolation for (R0, .., Rt; i)
        let big_r_i = PolynomialCommitment::eval_exponent_interpolation(
            threshold_plus1_identifiers,
            threshold_plus1_verifying_shares,
            Some(identifier),
        )?;

        // check the interpolated R values match the received ones
        if big_r_i != *verifying_share {
            return Err(ProtocolError::AssertionFailed(
                "Exponent interpolation check failed.".to_string(),
            ));
        }
    }
```
