### Title
Missing Proof-of-Correctness Validation for Participant Contributions in CKD Coordinator — (`File: src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `do_ckd_coordinator` function in the Confidential Key Derivation (CKD) protocol accepts `(big_y, big_c)` contributions from participants and aggregates them without any proof-of-correctness validation. A single malicious participant can submit arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that honest parties will accept as valid.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `CKDOutput` via `recv_from_others` and unconditionally adds the values together:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each participant is supposed to compute:
- `big_y_i = y_i * G1` (a random blinding element)
- `big_c_i = x_i * H(pk || app_id) + y_i * app_pk` (masked secret share contribution)

scaled by their Lagrange coefficient `lambda_i`. However, no zero-knowledge proof or any other mechanism is required to demonstrate that `(big_y_i, big_c_i)` was honestly derived from the participant's actual secret share `x_i`. The `recv_from_others` helper validates the **sender identity** (that the message came from a known participant), but performs no **content validation** on the group elements themselves. [2](#0-1) 

The correct computation in `compute_signature_share` is:

```rust
let big_s = hash_point * private_share.to_scalar();
let big_c = big_s + app_pk * y.0;
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
``` [3](#0-2) 

A malicious participant bypasses this entirely and sends arbitrary `(big_y, big_c)` values. Unlike DKG, where the threshold assumption means `t-1` malicious parties cannot corrupt the output, the CKD aggregation is a simple linear sum — **a single malicious participant is sufficient to corrupt the final output**.

---

### Impact Explanation

The coordinator outputs `CKDOutput { big_y, big_c }` which the application unmasks via:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
``` [4](#0-3) 

The expected result is `msk * H(pk || app_id)` — the confidential derived key. If any participant injects an arbitrary `delta` into `big_c`, the unmasked result becomes `msk * H(pk || app_id) + delta_residual`, which is a wrong key. The application accepts this corrupted output with no way to detect the manipulation, since there is no integrity check on the coordinator's output.

**Impact class:** High — Corruption of CKD outputs so honest parties accept an incorrect confidential derived key, permanently breaking the derivation for that `(app_id, app_pk)` pair.

---

### Likelihood Explanation

Any participant in the CKD protocol can trigger this. The attacker only needs to be one of the `n` participants — they do not need to be the coordinator, do not need a threshold of colluders, and do not need any special privilege beyond being included in the `participants` list. The attack requires no cryptographic break and is trivially executable by substituting arbitrary `G1` points in the message sent to the coordinator.

---

### Recommendation

Add a zero-knowledge proof of correct formation alongside each `(big_y, big_c)` contribution. Concretely, each participant should prove in zero-knowledge that:

- `big_y = y * G1` for some `y` they know, and
- `big_c = x_i * H(pk || app_id) + y * app_pk` for the same `y` and their committed secret share `x_i`

A standard Schnorr-style sigma protocol (similar to the proof-of-knowledge already used in DKG at `proof_of_knowledge` / `internal_verify_proof_of_knowledge` in `src/dkg.rs`) can achieve this without revealing `x_i` or `y`. [5](#0-4) [6](#0-5) 

The coordinator must verify each participant's proof before including their contribution in the aggregation.

---

### Proof of Concept

1. Run the CKD protocol with 3 participants and a coordinator.
2. One participant (the attacker) overrides their `compute_signature_share` output and instead sends `(big_y = G1_generator, big_c = G1_generator)` — arbitrary fixed points — to the coordinator.
3. The coordinator at lines 50–55 adds these values without any check.
4. The coordinator outputs `CKDOutput` containing the corrupted sum.
5. The application calls `unmask(app_sk)` and receives a value that is not `msk * H(pk || app_id)`.
6. The test in `src/confidential_key_derivation/protocol.rs` at line 278 (`assert_eq!(confidential_key, expected_confidential_key)`) would fail, confirming the corruption. [7](#0-6)

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

**File:** src/confidential_key_derivation/protocol.rs (L165-181)
```rust
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

**File:** src/confidential_key_derivation/protocol.rs (L272-280)
```rust
        // compute msk . H(pk, app_id)
        let confidential_key = ckd_output.unmask(app_sk);

        // H(pk || app_id) * msk
        let expected_confidential_key = hash_app_id_with_pk(&pk, &app_id) * msk;

        assert_eq!(
            confidential_key, expected_confidential_key,
            "Keys should be equal"
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
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

**File:** src/dkg.rs (L145-166)
```rust
fn internal_verify_proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: &mut DomainSeparator,
    participant: Participant,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: &Signature<C>,
) -> Result<(), ProtocolError> {
    // creates an identifier for the participant
    let id = participant.scalar::<C>();
    let vk_share = commitment
        .coefficients()
        .first()
        .ok_or_else(|| ProtocolError::AssertionFailed("Empty coefficient list".to_string()))?;

    let big_r = proof_of_knowledge.R();
    let z = proof_of_knowledge.z();
    let c = challenge::<C>(domain_separator, session_id, id, vk_share, big_r)?;
    if *big_r != <C::Group>::generator() * *z - vk_share.value() * c.to_scalar() {
        return Err(ProtocolError::InvalidProofOfKnowledge(participant));
    }
    Ok(())
}
```
