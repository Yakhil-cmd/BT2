### Title
Missing Proof of Correct Contribution in CKD Protocol Allows Malicious Participant to Corrupt Derived Confidential Secret — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The Confidential Key Derivation (CKD) protocol's coordinator blindly accumulates EC point contributions `(norm_big_y, norm_big_c)` from every participant with no zero-knowledge proof of correctness. A single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that decrypts to a wrong confidential derived key.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `(norm_big_y, norm_big_c)` pair and unconditionally adds them to the running sum:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

The values being summed are produced by `compute_signature_share`:

- `big_y = y * G` (random nonce)
- `big_s = hash_point * x_i` (secret share contribution)
- `big_c = big_s + app_pk * y` (ElGamal ciphertext component)
- `norm_big_y = lambda_i * big_y`, `norm_big_c = lambda_i * big_c` [2](#0-1) 

No proof is attached to the outgoing message in `do_ckd_participant`:

```rust
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
``` [3](#0-2) 

The coordinator has no way to verify that:
1. `norm_big_y` is `lambda_i * y_i * G` for any `y_i` the participant actually used.
2. `norm_big_c` encodes `lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)` using the participant's real secret share `x_i` and the same nonce `y_i`.

The library already contains a `dlogeq` proof primitive (`src/crypto/proofs/dlogeq.rs`) that proves knowledge of a scalar `x` satisfying `x*G = P0` and `x*H = P1` simultaneously — exactly the structure needed here — but it is not used in the CKD protocol. [4](#0-3) 

---

### Impact Explanation

The final `CKDOutput` is an ElGamal encryption of `msk * H(pk, app_id)` under `app_pk`. When a malicious participant injects arbitrary `(big_y_evil, big_c_evil)`, the coordinator computes:

```
Y_final  = Y_honest  + big_y_evil
C_final  = C_honest  + big_c_evil
```

The application decrypts `C_final - app_sk * Y_final`, which no longer equals `msk * H(pk, app_id)`. The derived confidential secret is silently wrong. This matches the **High** allowed impact: *Corruption of CKD outputs so honest parties accept unusable or inconsistent cryptographic outputs.*

---

### Likelihood Explanation

Any single participant in the CKD session can trigger this. The attacker needs only to deviate from the protocol by sending two arbitrary `G1` points instead of their honest contribution. No cryptographic capability beyond participation is required. The coordinator performs no check before accepting and summing the values.

---

### Recommendation

Each participant should attach a zero-knowledge proof of correct contribution alongside `(norm_big_y, norm_big_c)`. Concretely, a `dlogeq` proof (already present in `src/crypto/proofs/dlogeq.rs`) can prove that the same scalar `y_i` was used in both `big_y = y_i * G` and the `y_i * app_pk` term inside `big_c`, and a separate `dlog` proof (or commitment-based check) can bind `big_s` to the participant's committed public share. The coordinator must verify all proofs before accumulating contributions. [5](#0-4) 

---

### Proof of Concept

1. Honest participants `P1, P2` and malicious participant `P3` run `ckd(...)`.
2. `P3` overrides `compute_signature_share` output and sends `(G, G)` (the generator point for both components) to the coordinator.
3. The coordinator computes:
   - `Y_final = lambda_1*y_1*G + lambda_2*y_2*G + G`
   - `C_final = lambda_1*(x_1*H+y_1*A) + lambda_2*(x_2*H+y_2*A) + G`
4. The application decrypts `C_final - app_sk * Y_final`, which equals `msk*H(pk,app_id) + G - app_sk*G` — a value shifted by `(1 - app_sk)*G`, not the correct derived secret.
5. No error is raised; the coordinator returns the corrupted `CKDOutput` as if the protocol succeeded. [6](#0-5)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-31)
```rust
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

```

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

**File:** src/crypto/proofs/dlogeq.rs (L139-163)
```rust
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> Result<bool, ProtocolError>
where
    Element<C>: ConstantTimeEq,
{
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }

    transcript.message(NEAR_DLOGEQ_STATEMENT_LABEL, &statement.encode()?);

    let (phi0, phi1) = statement.phi(&proof.s.0);
    let big_k0 = phi0 - *statement.public0 * proof.e.0;
    let big_k1 = phi1 - *statement.public1 * proof.e.0;

    let enc = encode_two_points::<C>(&big_k0, &big_k1)?;

    transcript.message(NEAR_DLOGEQ_COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(NEAR_DLOGEQ_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    Ok(e == proof.e.0)
```
