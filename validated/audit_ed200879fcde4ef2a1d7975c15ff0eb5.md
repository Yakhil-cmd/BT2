### Title
Malicious Participant Can Corrupt CKD Output Without Cryptographic Verification — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary
The CKD coordinator aggregates each participant's `(norm_big_y, norm_big_c)` contribution by simple addition with no proof of correct formation. A single malicious participant can send arbitrary group elements, silently corrupting the final derived confidential key.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's output and unconditionally sums it: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

The intended invariant is that each honest participant `i` sends:

- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · A)`

so that the aggregate satisfies `C − Y · app_sk = x · H(pk ‖ app_id)`. [2](#0-1) 

There is **no zero-knowledge proof, no consistency check, and no binding** between a participant's `norm_big_c` and their known public key share. The coordinator has no way to distinguish a correctly formed contribution from an arbitrary pair of group elements.

The participant path (`do_ckd_participant`) simply computes and sends the share with no accompanying proof: [3](#0-2) 

---

### Impact Explanation

A malicious participant sends `(G, G)` or any arbitrary `(ElementG1, ElementG1)` pair. The coordinator adds these into the running sum. The resulting `CKDOutput` satisfies no useful algebraic relation: `C − Y · app_sk ≠ x · H(pk ‖ app_id)`. The application receives a silently wrong derived key with no error signal. This is **corruption of CKD outputs so honest parties accept unusable cryptographic outputs** — a **High** impact per the allowed scope.

---

### Likelihood Explanation

Any single participant in the CKD protocol can mount this attack. No leaked keys, no cryptographic breaks, and no external assumptions are required. The attacker only needs to deviate from the protocol by sending two arbitrary `G1` points instead of their correct contribution. The coordinator has no detection mechanism.

---

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation — specifically, a proof that `norm_big_c` is consistent with `norm_big_y`, the participant's public key share, and the public `app_pk`. A Chaum–Pedersen-style DLEQ proof over the BLS12-381 G1 group is the standard approach. The coordinator must verify each proof before adding the contribution to the aggregate.

---

### Proof of Concept

1. Honest participants run `compute_signature_share` and send correct `(norm_big_y, norm_big_c)` to the coordinator.
2. Malicious participant `P_m` instead sends `(ElementG1::generator(), ElementG1::generator())` — two arbitrary points — via `chan.send_private(waitpoint, coordinator, &(big_y, big_c))`.
3. The coordinator's loop at lines 50–55 adds these values unconditionally.
4. The final `CKDOutput` is `(Y + G, C + G)`, which satisfies no useful relation.
5. The application calls `ckd_output.unmask(app_sk)` and obtains a wrong key with no error returned, silently breaking the confidential key derivation for all consumers of this protocol run.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L17-33)
```rust
fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}
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
