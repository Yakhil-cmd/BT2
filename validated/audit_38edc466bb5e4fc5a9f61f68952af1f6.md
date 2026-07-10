### Title
Missing Proof-of-Correctness on CKD Participant Contributions Allows Malicious Participant to Corrupt Derived Confidential Key - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The Confidential Key Derivation (CKD) coordinator blindly aggregates `(norm_big_y, norm_big_c)` contributions from every participant with no cryptographic proof that each contribution was computed honestly. A single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that does not correspond to any valid derived key, permanently denying the application of a usable confidential key.

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's share and unconditionally adds it to the running sum: [1](#0-0) 

Each participant is supposed to compute, in `compute_signature_share`:

- `big_y = y * G` (random blinding point)
- `big_s = private_share * H(pk || app_id)` (BLS signature share)
- `big_c = big_s + y * app_pk` (ElGamal encryption of the BLS share)
- `norm_big_y = lambda_i * big_y`, `norm_big_c = lambda_i * big_c` [2](#0-1) 

The coordinator receives `(norm_big_y, norm_big_c)` over the channel and adds them directly: [3](#0-2) 

There is **no proof** that:
1. `norm_big_y` is a valid scalar multiple of the generator (i.e., `lambda_i * y * G` for the same `y` used in `norm_big_c`).
2. `norm_big_c` encodes the correct BLS share under the correct blinding (i.e., `lambda_i * (private_share_i * H(pk, app_id) + y * app_pk)`).

The codebase already contains a DLOGEQ proof system (`src/crypto/proofs/dlogeq.rs`) capable of proving that the same scalar `y` was used in both `big_y = y * G` and `big_c - big_s = y * app_pk`, but it is not applied here. [4](#0-3) 

### Impact Explanation

A malicious participant sends arbitrary `(norm_big_y', norm_big_c')` — for example, random group elements or the identity. The coordinator sums all contributions:

```
final_big_y = sum(lambda_i * big_y_i)   <- includes attacker's garbage
final_big_c = sum(lambda_i * big_c_i)   <- includes attacker's garbage
```

The `CKDOutput::unmask(app_sk)` call then computes `final_big_c - app_sk * final_big_y`, which will not equal `H(pk, app_id) * msk` (the intended confidential key). The output is silently wrong — no error is raised, and the coordinator returns a `Some(ckd_output)` that is cryptographically invalid. Every honest party that relies on this derived key receives a corrupted result with no indication of failure.

This matches the **High** impact class: *Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.*

### Likelihood Explanation

Any single participant in the CKD session can trigger this. The attacker needs only to be a legitimate protocol participant (holding a valid key share from DKG) and to deviate from the protocol by sending malformed `(norm_big_y, norm_big_c)` values. No cryptographic break, no leaked key, and no external assumption is required. The attack is trivially executable by any participant who wishes to deny the application a valid confidential key.

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a DLOGEQ proof demonstrating that the same scalar `y` was used in both components, and that `norm_big_c` encodes the correct BLS share. Concretely:

1. The participant proves knowledge of `y` such that `norm_big_y = lambda_i * y * G` and `norm_big_c - lambda_i * public_share_i * H(pk, app_id) = lambda_i * y * app_pk` using the existing `prove_with_nonce` / `verify` API in `src/crypto/proofs/dlogeq.rs`.
2. The coordinator verifies each proof before adding the contribution to the running sum, and aborts (identifying the malicious participant) if any proof fails.

### Proof of Concept

```
Setup: 3 participants, threshold = 3, honest coordinator = P1, malicious = P2.

1. P2 runs do_ckd_participant but instead of calling compute_signature_share,
   sends (norm_big_y' = G, norm_big_c' = G) — arbitrary non-zero points.

2. Coordinator P1 receives:
     from P3: (lambda_3 * y_3 * G,  lambda_3 * (big_s_3 + y_3 * app_pk))   [honest]
     from P2: (G, G)                                                          [malicious]

3. P1 computes:
     final_big_y = my_norm_big_y + lambda_3*y_3*G + G          <- corrupted
     final_big_c = my_norm_big_c + lambda_3*(big_s_3+y_3*app_pk) + G  <- corrupted

4. unmask(app_sk) = final_big_c - app_sk * final_big_y
                  ≠ H(pk, app_id) * msk

5. The coordinator returns Some(corrupted_ckd_output) with no error.
   The application derives a wrong confidential key silently.
```

The root cause is exclusively in `src/confidential_key_derivation/protocol.rs` lines 50–55, where participant contributions are aggregated without any cryptographic validity check.

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
