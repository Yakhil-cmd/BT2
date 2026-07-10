### Title
Malicious CKD Participant Can Send Arbitrary Shares to Corrupt Confidential Key Derivation Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator unconditionally accumulates `(big_y, big_c)` values received from every participant with no cryptographic verification that those values were honestly computed. A single malicious participant can substitute arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` whose `unmask` result is not `msk · H(pk, app_id)`.

---

### Finding Description

`do_ckd_coordinator` collects each participant's contribution and adds it directly into the running sum:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each honest participant is supposed to send `(λᵢ · yᵢ · G₁, λᵢ · (xᵢ · H(pk, app_id) + yᵢ · app_pk))` where `xᵢ` is their secret signing share. [2](#0-1) 

There is no zero-knowledge proof, no consistency check against the participant's public key share, and no Pedersen-style commitment binding `big_c` to `big_y`. The coordinator has no means to distinguish a correctly formed share from an arbitrary pair of G₁ elements.

The participant side simply computes and sends the values with no accompanying proof:

```rust
let (norm_big_y, norm_big_c) =
    compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
let waitpoint = chan.next_waitpoint();
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
``` [3](#0-2) 

This is structurally identical to the external report's root cause: an input that is supposed to be constrained (a referral address; here, a cryptographic share) is accepted and acted upon without any validity check.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The final `CKDOutput` is `(Y_total, C_total)`. The `unmask(app_sk)` operation computes `C_total − app_sk · Y_total`. If even one participant injects arbitrary `(Y', C')`, the result deviates from `msk · H(pk, app_id)` by `C' − app_sk · Y'`, which is non-zero with overwhelming probability for any random injection. The derived confidential key is therefore wrong and unusable by the TEE application. This matches the allowed impact: *"Corruption of … CKD outputs so honest parties accept … unusable cryptographic outputs."*

---

### Likelihood Explanation

**High.** Any participant in the CKD session is an attacker-controlled entry point. No special knowledge is required — sending `(G₁::identity(), G₁::identity())` or any random G₁ pair is sufficient to corrupt the output. The attack requires no interaction beyond normal protocol participation and is undetectable by the coordinator with the current code.

---

### Recommendation

Each participant must accompany their `(big_y, big_c)` with a zero-knowledge proof of correct formation. Concretely, a Chaum–Pedersen DLEQ proof can show that the discrete-log relationship between `big_y` and `big_c − xᵢ · H(pk, app_id)` with respect to `G₁` and `app_pk` is the same scalar `yᵢ`, and that `xᵢ` is consistent with the participant's public key share `vkᵢ = xᵢ · G₂`. The coordinator must verify all proofs before accumulating any share.

---

### Proof of Concept

1. Honest participants P₁…P_{n−1} each compute and send their correct `(λᵢ · yᵢ · G₁, λᵢ · (xᵢ · H(pk, app_id) + yᵢ · app_pk))`.
2. Malicious participant P_m sends `(G₁::identity(), G₁::identity())` (or any arbitrary pair) instead of its correct share.
3. The coordinator executes the loop at lines 50–55 and accumulates P_m's zero contribution, producing `Y_total = Σ_{i≠m} λᵢ yᵢ G₁` and `C_total = Σ_{i≠m} λᵢ (xᵢ H + yᵢ A)`.
4. `unmask(app_sk)` returns `C_total − app_sk · Y_total`, which equals `(msk − λ_m x_m) · H(pk, app_id)` — not `msk · H(pk, app_id)`.
5. The TEE application receives a wrong confidential key with no indication of failure; the `CKDOutput` is silently corrupted.

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
