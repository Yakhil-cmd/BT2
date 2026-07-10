### Title
Missing Proof of Correct Computation for CKD Participant Contributions Allows Malicious Participant to Corrupt CKD Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
In `do_ckd_coordinator`, the coordinator accepts each participant's CKD contribution `(norm_big_y, norm_big_c)` and sums them without any cryptographic proof that the contribution was correctly computed from the participant's actual signing share. A malicious participant can send arbitrary group elements, corrupting the final CKD output and causing honest parties to derive an incorrect, unusable confidential key. The codebase already contains a DLEQ proof implementation (`src/crypto/proofs/dlogeq.rs`) that could enforce correct computation, but it is not applied here — directly analogous to using `_mint()` when `_safeMint()` (with its recipient-compliance check) exists.

### Finding Description

In `do_ckd_coordinator` (lines 44–57 of `src/confidential_key_derivation/protocol.rs`), the coordinator collects contributions from all other participants and accumulates them unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

The honest computation each participant is supposed to perform (in `compute_signature_share`, lines 148–182) is:

- `big_y = y_i * G` (ephemeral randomness times generator)
- `big_c = x_i * H(pk ‖ app_id) + y_i * app_pk` (share contribution plus masked randomness)
- Both are Lagrange-weighted: `(λ_i * big_y, λ_i * big_c)`

The coordinator then sums all contributions to produce the final `CKDOutput`. The correctness of the output depends entirely on every participant having followed this computation honestly. There is **no proof** attached to each contribution verifying that `big_c` was formed using the participant's actual share `x_i` and the same ephemeral `y_i` used to form `big_y`.

The codebase already contains a DLEQ proof system at `src/crypto/proofs/dlogeq.rs` (the `Statement`, `Witness`, and `Proof` types). A DLEQ proof could enforce that `log_G(big_y) = log_{app_pk}(big_c − x_i * H(pk ‖ app_id))`, i.e., that the same `y_i` was used in both components. This is the "safe" version of accepting a contribution — but it is not used.

This is the direct analog of `_mint()` vs `_safeMint()`: a safer variant with a validity check exists in the codebase, but the code uses the unchecked path, accepting any group elements a participant sends.

### Impact Explanation

A malicious participant sends `(big_y + Δ_y, big_c + Δ_c)` for arbitrary group elements `Δ_y, Δ_c`. The coordinator accumulates these without rejection. The final output becomes:

- `Y' = Y + λ_malicious * Δ_y`
- `C' = C + λ_malicious * Δ_c`

When the application calls `unmask(app_sk)` to recover the confidential key, it computes `C' − Y' * app_sk`, which equals:

```
msk * H(pk ‖ app_id) + λ_malicious * (Δ_c − Δ_y * app_sk)
```

Since the malicious participant does not know `app_sk`, they cannot make this term vanish, so the derived confidential key is permanently incorrect and unusable. Honest parties accept this corrupted output with no indication of failure.

**Impact class:** High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.

### Likelihood Explanation

Any single participant in the CKD protocol can execute this attack. No privileged access, leaked keys, or external assumptions are required. The attacker simply deviates from the protocol by sending arbitrary group elements instead of correctly computed ones. The coordinator has no mechanism to detect or reject the malformed contribution. The attack is trivially executable by any participant at any CKD invocation.

### Recommendation

Require each participant to attach a DLEQ proof to their contribution, proving that the same discrete logarithm `y_i` was used in both `big_y = y_i * G` and the `y_i * app_pk` component of `big_c`. The coordinator must verify this proof before accumulating the contribution. The `dlogeq.rs` proof system already present in `src/crypto/proofs/dlogeq.rs` provides the necessary `Statement`, `Witness`, and `Proof` types and can be adapted for this purpose. Contributions failing proof verification should be rejected and the offending participant identified.

### Proof of Concept

1. Honest participants P_1 … P_{n−1} compute and send correct `(λ_i * big_y_i, λ_i * big_c_i)`.
2. Malicious participant P_n computes their legitimate values but instead sends `(λ_n * big_y_n + Δ_y, λ_n * big_c_n + Δ_c)` for arbitrary non-zero group elements `Δ_y, Δ_c`.
3. The coordinator (lines 50–55 of `protocol.rs`) accumulates all contributions without any proof check.
4. The final `CKDOutput` is `(Y + Δ_y, C + Δ_c)`.
5. The application calls `ckd_output.unmask(app_sk)` and receives `msk * H(pk ‖ app_id) + (Δ_c − Δ_y * app_sk)` — an incorrect value that does not equal the intended confidential key for any non-trivial `Δ_y, Δ_c` chosen without knowledge of `app_sk`.
6. The CKD protocol completes successfully from the perspective of all honest parties; no error is raised. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** src/crypto/proofs/dlogeq.rs (L43-100)
```rust
impl<C: Ciphersuite> Statement<'_, C> {
    /// Calculate the homomorphism we want to prove things about.
    fn phi(&self, x: &Scalar<C>) -> (Element<C>, Element<C>) {
        (C::Group::generator() * *x, *self.generator1 * *x)
    }

    /// Encode into Vec<u8>: some sort of serialization
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut enc = Vec::new();
        enc.extend_from_slice(NEAR_DLOGEQ_ENCODE_LABEL_STATEMENT);
        // None of the following calls should panic as neither public and generator are identity
        let ser0 = element_into::<C>(self.public0, NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC0)?;
        let ser1 = element_into::<C>(self.generator1, NEAR_DLOGEQ_ENCODE_LABEL_GENERATOR1)?;
        let ser2 = element_into::<C>(self.public1, NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC1)?;
        enc.extend_from_slice(&ser0);
        enc.extend_from_slice(&ser1);
        enc.extend_from_slice(&ser2);
        Ok(enc)
    }
}

/// The private witness for this proof.
/// This holds the scalar the prover needs to know.
#[derive(Clone, Copy)]
pub struct Witness<C: Ciphersuite> {
    pub x: SerializableScalar<C>,
}

/// Represents a proof of the statement.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct Proof<C: Ciphersuite> {
    e: SerializableScalar<C>,
    s: SerializableScalar<C>,
}

/// Encodes two EC points into a vec including the identity point.
/// Should be used with HIGH precaution as it allows serializing the identity point
/// deviating from the standard
fn encode_two_points<C: Ciphersuite>(
    point_1: &Element<C>,
    point_2: &Element<C>,
) -> Result<Vec<u8>, ProtocolError> {
    // Create a serialization of big_k
    let mut ser1 = C::Group::serialize(point_1)
        .map_err(|_| ProtocolError::IdentityElement)?
        .as_ref()
        .to_vec();

    let ser2 = C::Group::serialize(point_2)
        .map_err(|_| ProtocolError::IdentityElement)?
        .as_ref()
        .to_vec();

    ser1.extend_from_slice(b" and ");
    ser1.extend_from_slice(&ser2);
    Ok(ser1)
}
```
