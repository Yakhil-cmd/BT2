### Title
Malicious Participant Can Corrupt CKD Output by Injecting Arbitrary Group Elements Without Proof of Correct Formation — (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The CKD coordinator unconditionally accumulates `(norm_big_y, norm_big_c)` contributions from every participant with no proof that each contribution is correctly formed from the participant's actual secret share. A single malicious participant can inject arbitrary BLS12-381 G1 elements, silently corrupting the aggregated `CKDOutput` and therefore the confidential derived key produced by the coordinator.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator initialises its own share and then loops over every other participant's message, adding each received pair directly to the running sum: [1](#0-0) 

```rust
let (mut norm_big_y, mut norm_big_c) =
    compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

let waitpoint = chan.next_waitpoint();
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

The honest computation each participant is supposed to perform is: [2](#0-1) 

```
big_y  = y · G₁                          (random blinding)
big_s  = xᵢ · H(pk ‖ app_id)            (secret-share contribution)
big_c  = big_s + y · app_pk             (masked contribution)
norm_big_y = λᵢ · big_y
norm_big_c = λᵢ · big_c
```

The participant sends these values privately to the coordinator: [3](#0-2) 

There is **no zero-knowledge proof, no commitment, and no binding** between the transmitted `(norm_big_y, norm_big_c)` and the participant's actual secret share `xᵢ`. The coordinator has no mechanism to detect that a participant deviated.

By contrast, the DKG layer does enforce correctness: every participant must supply a proof of knowledge of their secret coefficient before their commitment is accepted: [4](#0-3) [5](#0-4) 

No equivalent protection exists in the CKD layer.

---

### Impact Explanation

The `CKDOutput` is consumed by the application via `unmask(app_sk)`, which computes:

```
confidential_key = Σ(λᵢ · big_cᵢ) − app_sk · Σ(λᵢ · big_yᵢ)
```

This equals `msk · H(pk ‖ app_id)` only when every participant contributes honestly. If even one participant injects arbitrary `(big_y′, big_c′)`, the sum is shifted by an attacker-controlled offset and the unmasked result is a random, attacker-influenced group element — not the legitimate confidential key.

**Allowed impact matched**: *High — Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.*

The coordinator, which is an honest party, receives and stores a `CKDOutput` it believes is correct. Any downstream TEE application that relies on this key will silently operate on a corrupted secret.

---

### Likelihood Explanation

- The attacker only needs to be **one participant** in the CKD session — a role that is explicitly granted by the caller of `ckd()`.
- The attack requires sending two arbitrary G1 points instead of the honest computation; no cryptographic capability is needed.
- The coordinator has zero ability to distinguish a malicious contribution from an honest one.
- The corruption is silent: `do_ckd_coordinator` returns `Ok(Some(ckd_output))` regardless.

---

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation — specifically, a proof that:

1. `norm_big_y = λᵢ · yᵢ · G₁` for some scalar `yᵢ`, and
2. `norm_big_c = λᵢ · (xᵢ · H(pk ‖ app_id) + yᵢ · app_pk)` where `xᵢ` is consistent with the participant's public verification share from the DKG output.

A standard approach is a Chaum–Pedersen / Schnorr proof over the pair `(norm_big_y, norm_big_c − λᵢ · xᵢ · H(pk ‖ app_id))` relative to the bases `(G₁, app_pk)`. The coordinator must verify all proofs before accumulating any contribution, mirroring the `verify_proof_of_knowledge` pattern already present in `src/dkg.rs`.

---

### Proof of Concept

```
Setup:
  participants = [P1 (coordinator), P2 (honest), P3 (malicious)]
  threshold = 2
  (msk, shares x1, x2, x3) produced by DKG
  app_id, app_pk

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L27-32)
```rust
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
```

**File:** src/confidential_key_derivation/protocol.rs (L44-56)
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

**File:** src/dkg.rs (L118-141)
```rust
fn proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: &mut DomainSeparator,
    me: Participant,
    coefficients: &Polynomial<C>,
    coefficient_commitment: &PolynomialCommitment<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<Signature<C>, ProtocolError> {
    // creates an identifier for the participant
    let id = me.scalar::<C>();
    let vk_share = coefficient_commitment.eval_at_zero()?;

    // pick a random k_i and compute R_id = g^{k_id},
    // Step 2.5
    let (k, big_r) = <C>::generate_nonce(rng);

    // Step 2.6
    // compute H(domain_separator, id, me, g^{a_0}, R_id) as a scalar
    let hash = challenge::<C>(domain_separator, session_id, id, &vk_share, &big_r)?;
    let a_0 = coefficients.eval_at_zero()?.0;
    // Step 2.7
    let mu = k + a_0 * hash.to_scalar();
    Ok(Signature::new(big_r, mu))
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
