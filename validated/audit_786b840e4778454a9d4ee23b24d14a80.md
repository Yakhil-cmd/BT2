### Title
Missing Verification of Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
In `do_ckd_coordinator`, the coordinator receives `(norm_big_y, norm_big_c)` from each participant and accumulates them with no proof of correctness. A malicious participant can inject arbitrary group elements, causing every honest party to accept a corrupted CKD output and derive a wrong confidential key.

### Finding Description
The analog to "missing balance checks before/after token transfer" is: receiving cryptographic share contributions without verifying the received values match what was committed to.

In `do_ckd_coordinator` the coordinator collects each participant's output and blindly adds it:

```rust
// src/confidential_key_derivation/protocol.rs lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

The honest computation in `compute_signature_share` produces:

- `norm_big_y = lambda_i * y_i * G`
- `norm_big_c = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)` [2](#0-1) 

There is **no zero-knowledge proof, no commitment, and no consistency check** that the received `big_c` is correctly formed relative to `big_y` and the participant's secret share `x_i`. The coordinator cannot distinguish a legitimate contribution from an arbitrary pair of group elements.

Compare this to the DKG protocol, which does enforce correctness: every commitment is hash-bound in round 1 (`verify_commitment_hash`) and every share is verified against the committed polynomial (`validate_received_share`). [3](#0-2) 

No equivalent protection exists in the CKD path.

### Impact Explanation
**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The final CKD output is `(Y, C)` where `C = msk * H(pk, app_id) + Y * app_sk`. The application recovers the confidential key via `unmask(app_sk) = C - app_sk * Y = msk * H(pk, app_id)`.

If a malicious participant sends `big_c' = big_c_legitimate + delta` for any attacker-chosen group element `delta`, the coordinator computes `C' = C + delta`. Every honest party then accepts `(Y, C')` as the valid output. When the application calls `unmask(app_sk)`, it receives `msk * H + delta` — a permanently wrong confidential key — with no indication of failure. The derived secret is silently corrupted.

### Likelihood Explanation
Any single participant in the CKD protocol can trigger this. No special privilege is required beyond being a listed participant. The attack is a single-message substitution with no cryptographic barrier.

### Recommendation
Each participant must accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation — for example a Chaum-Pedersen discrete-log equality proof showing that `big_c - lambda_i * x_i * H` and `big_y` share the same discrete log base (`app_pk` and `G` respectively, both scaled by `lambda_i * y_i`). The coordinator must verify this proof before accumulating the contribution, mirroring the `validate_received_share` pattern already used in DKG.

### Proof of Concept
1. Malicious participant `P_m` computes their legitimate `(norm_big_y_m, norm_big_c_m)` per `compute_signature_share`.
2. `P_m` instead sends `(norm_big_y_m, norm_big_c_m + delta)` to the coordinator for any chosen non-identity `delta`.
3. The coordinator executes lines 50-55 and accumulates `C' = C_honest + delta`.
4. The coordinator returns `CKDOutput::new(Y, C')` as the protocol result.
5. The application calls `ckd_output.unmask(app_sk)` and receives `C' - app_sk * Y = msk * H + delta`.
6. The derived confidential key is `msk * H + delta` — wrong for every honest party — and the protocol reports success with no error. [4](#0-3)

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

**File:** src/dkg.rs (L259-286)
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
}
```
