### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator unconditionally accumulates `(big_y, big_c)` contributions from every participant with no cryptographic verification. A single malicious participant can submit arbitrary group elements, silently corrupting the final derived key that all honest parties accept as valid.

### Finding Description
In `do_ckd_coordinator`, the coordinator receives each participant's `CKDOutput` and blindly adds it to the running totals:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each honest participant is supposed to send `(λ_i · y_i · G, λ_i · (x_i · H(pk, app_id) + y_i · app_pk))`. The coordinator performs no zero-knowledge proof check, no commitment-then-reveal binding, and no consistency check between `big_y` and `big_c`. There is no analogue of a "SafeERC20 wrapper" — the coordinator simply trusts that every received pair is well-formed. [2](#0-1) 

The participant-side computation in `compute_signature_share` is correct in isolation, but nothing prevents a malicious participant from calling `chan.send_private` with arbitrary `ElementG1` values instead of the protocol-mandated ones. [3](#0-2) 

### Impact Explanation
The final `CKDOutput` `(Y, C)` is an ElGamal ciphertext of `msk · H(pk, app_id)` under `app_pk`. If a malicious participant injects `(Δ_Y, Δ_C)` instead of their correct share, the coordinator produces:

```
Y'  = Y_honest + Δ_Y  − λ_m · y_m · G
C'  = C_honest + Δ_C  − λ_m · (x_m · H(pk,app_id) + y_m · app_pk)
```

The application then calls `ckd_output.unmask(app_sk)` which computes `C' − Y' · app_sk`, yielding a value that is **not** `msk · H(pk, app_id)`. All honest parties accept this corrupted output because there is no post-aggregation verification step. This directly matches:

> **High: Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

### Likelihood Explanation
Any single participant in the CKD session is a sufficient attacker. The attack requires only that the malicious party deviate from the protocol when sending their private message to the coordinator — a trivial one-message substitution with no special cryptographic capability required. There is no detection mechanism, so the corruption is silent and the honest parties have no way to identify the culprit or retry with a corrected value.

### Recommendation
Require each participant to accompany their `(big_y, big_c)` with a non-interactive zero-knowledge proof of correct formation — specifically, a proof that `big_c − big_y · app_pk = x_i · H(pk, app_id)`, binding the ciphertext to the participant's public key share. This is the direct analog of using `SafeERC20.safeTransferFrom` instead of a raw `transferFrom`: it wraps the untrusted external input with a validity check before accepting it.

### Proof of Concept
1. Honest participants run `ckd()` with valid `KeygenOutput` and `app_id`.
2. The malicious participant overrides the protocol and sends `(G, G)` (the generator point for both components) to the coordinator instead of the correctly computed share.
3. The coordinator sums all contributions including the malicious `(G, G)`.
4. The coordinator returns a `CKDOutput` where `Y` and `C` are each offset by one generator point from their correct values.
5. Every honest party calls `ckd_output.unmask(app_sk)` and obtains `msk · H(pk, app_id) + G − G · app_sk`, which is not the correct confidential key.
6. No error is raised; the corrupted key is silently accepted.

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
