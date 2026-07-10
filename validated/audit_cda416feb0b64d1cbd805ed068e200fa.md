### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `do_ckd_coordinator` function aggregates participant-supplied group elements into the final `CKDOutput` with no validation that each participant's contribution was honestly computed. A single malicious participant can substitute arbitrary G1 elements, silently corrupting the derived key the coordinator returns. Unlike the ECDSA signing protocols, which verify the assembled signature before returning it, the CKD protocol has no equivalent post-aggregation check.

---

### Finding Description

`do_ckd_coordinator` collects one `CKDOutput` per participant and unconditionally adds each field into the running totals: [1](#0-0) 

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

Each honest participant is supposed to send:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · A)
```

where `x_i` is the participant's private share, `y_i` is a fresh random scalar, and `A` is the application public key. [2](#0-1) 

There is no zero-knowledge proof, Pedersen commitment, or any other mechanism that binds the transmitted `(norm_big_y, norm_big_c)` to the participant's actual key share. A malicious participant can transmit any two G1 points — including the identity, the generator, or a point chosen to bias the output toward an attacker-controlled value — and the coordinator will accept and aggregate them without error.

By contrast, both ECDSA signing implementations verify the assembled signature before returning it: [3](#0-2) [4](#0-3) 

The CKD protocol has no equivalent post-aggregation integrity check.

---

### Impact Explanation

The `CKDOutput` is later unmasked by the application with its secret scalar `a`: [5](#0-4) 

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
```

If either `big_y` or `big_c` was corrupted by a malicious participant, `unmask` silently returns a wrong G1 point instead of `msk · H(pk ‖ app_id)`. The coordinator and the application have no way to distinguish this from a correct output. This is a **corruption of CKD output so honest parties accept an unusable cryptographic output**, matching the allowed High impact.

---

### Likelihood Explanation

Any single participant in the protocol can mount this attack. The entry path is direct: the participant simply sends arbitrary bytes that deserialize as a valid `CKDOutput` struct (two G1 points). No special privilege, leaked key, or external assumption is required. The coordinator performs no check on the received values before incorporating them.

---

### Recommendation

Add a non-interactive zero-knowledge proof (e.g., a Chaum–Pedersen DLEQ proof) that each participant's `norm_big_c_i` is consistent with their public verification share and the agreed `app_id`. Specifically, each participant should prove in zero knowledge that:

```
norm_big_c_i - norm_big_y_i · A  =  λ_i · x_i · H(pk ‖ app_id)
```

where `λ_i · x_i · H(pk ‖ app_id)` can be verified by the coordinator using the participant's public share from the DKG output. This mirrors the proof-of-knowledge pattern already used in `do_keyshare` during DKG. [6](#0-5) 

---

### Proof of Concept

1. Honest participants run `ckd(...)` normally.
2. The malicious participant intercepts the protocol at the `send_private` call in `do_ckd_participant` and instead sends `(G1::generator(), G1::generator())`.
3. The coordinator's loop at lines 50–55 of `protocol.rs` adds these points to `norm_big_y` and `norm_big_c` without complaint.
4. The returned `CKDOutput` contains `big_y = Σ(honest norm_big_y) + G` and `big_c = Σ(honest norm_big_c) + G`.
5. The application calls `ckd_output.unmask(app_sk)` and receives `msk · H(pk ‖ app_id) + G - G · app_sk`, which is not the expected derived key.
6. No error is raised at any point; the corruption is silent. [7](#0-6)

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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L129-133)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L159-163)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
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
