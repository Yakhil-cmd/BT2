### Title
Malicious Participant Can Submit Arbitrary CKD Shares Without Proof of Correctness, Corrupting the Coordinator's Output - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator in `do_ckd_coordinator` aggregates `(norm_big_y, norm_big_c)` contributions from every participant with no cryptographic proof that each contribution was computed from the participant's actual key share. Any malicious participant in the protocol can send arbitrary group elements in place of their legitimate share, causing the coordinator to produce a corrupted `CKDOutput` that the app cannot use. This is the direct analog of the `Earning.sol` `update()` bug: just as any caller could inject arbitrary earnings without authorization, any protocol participant can inject arbitrary CKD material without proving it was derived from their secret share.

---

### Finding Description

**Root cause — `src/confidential_key_derivation/protocol.rs`, lines 35–57:**

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

    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();   // ← no proof check
        norm_big_c += participant_output.big_c();   // ← no proof check
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}
``` [1](#0-0) 

The coordinator simply sums every received `(Y_i, C_i)` pair. There is no accompanying zero-knowledge proof, commitment binding, or consistency check that forces each sender to use their actual Lagrange-weighted key share `x_i`. The honest computation is:

```
S_i = x_i · H(pk, app_id)
C_i = S_i + y_i · A
Y_i = y_i · G
``` [2](#0-1) 

A malicious participant instead sends `(Y_i', C_i')` of their choice. Because `do_ckd_participant` simply calls `compute_signature_share` and forwards the result privately to the coordinator with no binding proof, a malicious node can replace that call with any two group elements: [3](#0-2) 

The network layer guarantees authenticated channels (sender identity is known), but it provides no guarantee that the *content* of a private message is correctly derived from the sender's secret share. [4](#0-3) 

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The final aggregated `(Y, C)` will not equal `(msk · H(pk, app_id) + a·Y_agg, Y_agg)`. When the TEE app computes `sig = C − a·Y` and attempts BLS verification against the known public key `pk`, the check fails. The app receives an unusable derived key. Because the coordinator has no way to identify which participant sent the bad share, the protocol cannot self-heal; the entire CKD session is wasted and must be retried after identifying and excluding the malicious node through an out-of-band process.

---

### Likelihood Explanation

Any single participant in the CKD session can trigger this. No privileged access, leaked key material, or cryptographic break is required — the attacker only needs to be a legitimate (but malicious) member of the participant list and to send two arbitrary `G1` points instead of their honest contribution. The attack is trivially executable on every CKD invocation.

---

### Recommendation

Require each participant to accompany their `(Y_i, C_i)` contribution with a non-interactive zero-knowledge proof of correct computation — specifically a proof of knowledge of `(x_i, y_i)` such that:

- `Y_i = y_i · G`
- `C_i = x_i · H(pk, app_id) + y_i · A`
- `x_i` is consistent with the participant's public verification share from the DKG output

A standard Schnorr-style sigma protocol (similar to the proof-of-knowledge already used in `do_keyshare` for DKG commitments) suffices. The coordinator must verify this proof before incorporating any participant's contribution into the running sum. [5](#0-4) 

---

### Proof of Concept

1. Run a CKD session with `n ≥ 2` participants, one of which is malicious.
2. The malicious participant, instead of calling `compute_signature_share`, constructs arbitrary `(Y_bad, C_bad)` in `G1` and sends them privately to the coordinator at the expected waitpoint.
3. The coordinator's loop at lines 50–55 adds `Y_bad` and `C_bad` into the running totals without any check.
4. The coordinator returns `CKDOutput::new(norm_big_y + Y_bad_delta, norm_big_c + C_bad_delta)`.
5. The TEE app computes `sig = C_corrupted − a · Y_corrupted`, which is not a valid BLS signature over `H(pk, app_id)` under `pk`.
6. BLS verification fails; the app cannot derive its key. [6](#0-5)

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

**File:** docs/network-layer.md (L9-10)
```markdown
- **Authenticated Channels:** All messages are sent over authenticated channels. Senders' identities are always verifiable.
- **Confidentiality for Private Messages:** Channels used for private messages (`send_private`) must be encrypted.
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
