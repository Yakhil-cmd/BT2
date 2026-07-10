### Title
Malicious CKD Participant Can Corrupt Coordinator Output by Sending Shares Computed for a Different `app_id` or `app_pk` — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary

The CKD coordinator aggregates participant shares without verifying that each share was computed for the agreed `app_id` and `app_pk`. A single malicious participant can substitute a share computed under a different application identifier or a different application public key. The coordinator blindly sums all received shares, producing a silently corrupted `CKDOutput` that decrypts to an incorrect confidential key. No error is raised and no honest party detects the substitution.

### Finding Description

The external report's vulnerability class is **transcript confusion**: a caller supplies an identifier that is never validated against the resource that was actually created, so a malicious actor can redirect the operation onto a different resource. The analog here is that each CKD participant supplies a cryptographic share that is never validated against the session's agreed `app_id` / `app_pk`, so a malicious participant can redirect the aggregation onto a different application context.

**Root cause — `do_ckd_coordinator`** [1](#0-0) 

```rust
async fn do_ckd_coordinator(...) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    let waitpoint = chan.next_waitpoint();
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();   // ← no verification
        norm_big_c += participant_output.big_c();   // ← no verification
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}
```

The coordinator receives raw `(big_y, big_c)` group elements from every participant and adds them unconditionally. There is no check that each received pair was produced by `compute_signature_share` with the same `app_id` and `app_pk` that the coordinator itself used.

**What an honest participant computes** [2](#0-1) 

```
big_s  = private_share_i · H(pk ‖ app_id)
big_c  = big_s + app_pk · y_i
big_y  = y_i · G
norm_big_y = λ_i · big_y
norm_big_c = λ_i · big_c
```

The correct aggregate is:
```
big_C = msk · H(pk ‖ app_id) + app_pk · Σ(λ_i · y_i)
big_Y = Σ(λ_i · y_i) · G
```
which decrypts to `msk · H(pk ‖ app_id)`.

**What a malicious participant can inject**

A malicious participant `m` instead computes their share using `app_id'` (any different identifier) or `app_pk' = 0`:

```
big_c_m = λ_m · private_share_m · H(pk ‖ app_id')   (using app_pk' = 0)
big_y_m = λ_m · y_m · G                              (unchanged)
```

The coordinator's aggregate becomes:
```
big_C' = (msk − λ_m · private_share_m) · H(pk ‖ app_id)
       + λ_m · private_share_m · H(pk ‖ app_id')
       + app_pk · Σ_{j≠m}(λ_j · y_j)
```

The client decrypts `big_C' − app_sk · big_Y'` and obtains a value that differs from `msk · H(pk ‖ app_id)` by a term the malicious participant controls. The output is silently wrong.

**Contrast with the signing protocol**

In `do_sign_coordinator` the coordinator performs a final `sig.verify(&public_key, &msg_hash)` check after aggregation, so a corrupted share is caught immediately. [3](#0-2) 

No equivalent verification exists in `do_ckd_coordinator`.

### Impact Explanation

A single malicious participant causes the coordinator to emit a `CKDOutput` whose `unmask` result is an incorrect group element. Any TEE or client that uses this output to derive a confidential key will silently derive the wrong key. Depending on the application, this means:

- Data encrypted under the expected key cannot be decrypted.
- Data encrypted under the corrupted key may be decryptable by the malicious participant (who knows the injected delta).

This is **corruption of a CKD output so honest parties accept an unusable or attacker-influenced cryptographic output**, matching the High impact tier.

### Likelihood Explanation

Any participant in the CKD session can trigger this. The participant need only deviate from the protocol in `compute_signature_share` — a one-line change to use a different `app_id` or set `app_pk = G1::identity()`. No special privilege, no key material beyond their own share, and no external assumption is required. The coordinator has no way to distinguish a legitimate share from a malicious one.

### Recommendation

The coordinator must verify that each received share is consistent with the agreed session context. Two complementary approaches:

1. **Commitment-then-reveal**: Before the share exchange, each participant broadcasts a hash commitment `H(norm_big_y ‖ norm_big_c ‖ app_id ‖ app_pk ‖ participant_id)`. After receiving the openings, the coordinator checks that every opening matches its commitment and that `app_id` and `app_pk` are the expected values.

2. **Zero-knowledge proof of correct computation**: Each participant attaches a NIZK proof that their `(norm_big_y, norm_big_c)` was computed from their committed signing share and the public `app_id` / `app_pk`. This is the stronger fix and aligns with the proof-of-knowledge pattern already used in `do_keyshare`. [4](#0-3) 

### Proof of Concept

```
Setup:
  participants = [P1 (coordinator), P2 (honest), P3 (malicious)]
  app_id  = b"target_app"
  app_pk  = a · G   (application keypair)

Honest execution:
  Each Pi sends (λ_i · y_i · G,  λ_i · (x_i · H(pk‖app_id) + a·G · y_i))
  Coordinator aggregates → correct CKDOutput
  Client unmasks → msk · H(pk‖app_id)  ✓

Attack (P3 uses app_pk' = G1::identity()):
  P3 sends (λ_3 · y_3 · G,  λ_3 · x_3 · H(pk‖app_id))
    — the app_pk term is dropped entirely
  Coordinator aggregates without complaint
  Client unmasks → msk · H(pk‖app_id) − a · λ_3 · y_3 · G  ✗

P3 knows λ_3 · y_3 and a (if app_sk is known to P3) and can therefore
compute the delta, making the corrupted output predictable to the attacker.
```

The attack requires no changes to the library's public API; it is exercisable by any caller that controls one participant's `rng` or `key_pair` input to `ckd()`. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L35-58)
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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L129-133)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
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
