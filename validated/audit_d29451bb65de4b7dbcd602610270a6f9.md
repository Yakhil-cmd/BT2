### Title
Missing Validation of Received CKD Contributions Enables Malicious Participant to Corrupt Confidential Key Derivation Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
In `do_ckd_coordinator`, the coordinator accumulates `CKDOutput` values from all participants by direct addition, with no proof of correctness and no check that received group elements are non-identity. A malicious participant can send crafted or zero (identity) values for `big_y` and `big_c`, causing the coordinator to compute and distribute an incorrect confidential derived key that honest parties accept as valid.

### Finding Description

The `do_ckd_coordinator` function receives each participant's `(big_y, big_c)` pair and unconditionally adds them to the running sum:

```rust
// src/confidential_key_derivation/protocol.rs, lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each honest participant is supposed to compute and send:

```
big_y  = y_i * G                              (random nonce commitment)
big_c  = x_i * H(pk, app_id) + y_i * app_pk  (ElGamal-style encryption of secret share)
```

scaled by their Lagrange coefficient `lambda_i`: [2](#0-1) 

The coordinator then assembles `CKDOutput::new(sum_Y, sum_C)` and the consumer calls `unmask(app_sk)` which computes `sum_C - app_sk * sum_Y` to recover `msk * H(pk, app_id)`.

**What is missing:**

1. **No proof of correctness** — there is no zero-knowledge proof that a participant's `big_c` was formed using the same nonce `y_i` as their `big_y`, nor that it encodes their actual secret share `x_i`. The analogous triple-generation protocol enforces this with `dlogeq` proofs: [3](#0-2) 

No such proof exists in the CKD contribution path.

2. **No identity-element check** — the coordinator never verifies that received `big_y` or `big_c` are non-identity `G1` elements. The BLS signature verifier does perform this check on its inputs: [4](#0-3) 

but the CKD coordinator does not.

**Exploit flow:**

A malicious participant sends `big_y = 𝒪` (identity) and `big_c = 𝒪` (identity) instead of their honest contribution. The coordinator computes:

```
sum_Y = Σ_{j ≠ i} λ_j · y_j · G
sum_C = Σ_{j ≠ i} λ_j · (x_j · H + y_j · app_pk)
```

`unmask(app_sk)` then yields:

```
sum_C - app_sk · sum_Y = (Σ_{j ≠ i} λ_j · x_j) · H  ≠  msk · H
```

The derived confidential key is silently wrong by exactly `λ_i · x_i · H`. Honest parties have no way to detect this because the coordinator produces a single aggregated output with no per-participant accountability.

### Impact Explanation

A single malicious participant can cause the coordinator to output a corrupted `CKDOutput`. Every honest party that consumes this output will derive an incorrect confidential key and accept it as valid. This matches the allowed **High** impact: *Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.*

Because the CKD protocol has no threshold parameter — all participants must contribute — even one malicious participant is sufficient to corrupt every CKD invocation they participate in. [5](#0-4) 

### Likelihood Explanation

Any participant enrolled in a CKD session can trigger this with zero cryptographic capability — they simply send identity elements or arbitrary valid curve points instead of their honest contribution. No privileged access, no leaked keys, and no external oracle is required. The attack is deterministic and repeatable for every CKD call that includes the malicious participant.

### Recommendation

1. **Add a Chaum-Pedersen (dlog-equality) proof** for each participant's contribution, proving that `big_c` and `big_y` share the same nonce `y_i` and that `big_c` encodes the correct secret share. The `dlogeq` infrastructure already exists in `src/crypto/proofs/dlogeq.rs` and is used in triple generation.

2. **Reject identity elements** — after deserialization, check that both `big_y` and `big_c` are not the `G1` identity, mirroring the check already present in `verify_signature`: [6](#0-5) 

3. **Bind contributions to public key shares** — include the participant's public key share in the proof statement so the verifier can confirm the secret share used in `big_c` matches the committed public share from DKG.

### Proof of Concept

```
Setup: 3 participants A, B, C (C is malicious). All hold shares x_A, x_B, x_C of msk.

Step 1: A and B compute honest (big_y, big_c) pairs and send them to coordinator.
Step 2: C sends (big_y=𝒪, big_c=𝒪) — identity elements — to coordinator.
Step 3: Coordinator sums without validation:
          sum_Y = λ_A·y_A·G + λ_B·y_B·G  (C's zero contribution silently dropped)
          sum_C = λ_A·(x_A·H + y_A·P) + λ_B·(x_B·H + y_B·P)
Step 4: Coordinator outputs CKDOutput(sum_Y, sum_C).
Step 5: Consumer calls unmask(app_sk):
          result = sum_C - app_sk·sum_Y
                 = (λ_A·x_A + λ_B·x_B)·H
                 ≠ msk·H  (missing λ_C·x_C·H)
Step 6: Honest parties accept the wrong confidential derived key with no error.
```

The coordinator at line 56 constructs `CKDOutput::new(norm_big_y, norm_big_c)` from the corrupted sums and returns it as a valid result: [7](#0-6)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L56-57)
```rust
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L477-491)
```rust
                let statement = dlogeq::Statement::<C> {
                    public0: &big_e_j_zero.index(from)?.value(),
                    generator1: &big_f.eval_at_zero()?.value(),
                    public1: &big_c_j,
                };

                if !dlogeq::verify(
                    &mut transcript.fork(b"dlogeq0", &from.bytes()),
                    statement,
                    their_phi_proof,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlogeq proof from {from:?} failed to verify"
                    )));
                }
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L223-230)
```rust
    let element1: G1Affine = signature.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return Err(frost_core::Error::InvalidSignature);
    }
    let element2: G2Affine = verifying_key.to_element().into();
    if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
        return Err(frost_core::Error::MalformedVerifyingKey);
    }
```
