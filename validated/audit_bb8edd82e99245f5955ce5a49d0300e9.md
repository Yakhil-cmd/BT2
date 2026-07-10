### Title
Missing Proof of Correct Computation for Participant Shares in CKD Protocol Allows Malicious Participant to Corrupt Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator blindly accumulates `big_y` and `big_c` group elements received from participants without any zero-knowledge proof or consistency check. A single malicious participant can send arbitrary BLS12-381 G1 elements, causing the coordinator to produce a corrupted `CKDOutput` that yields an incorrect confidential key when unmasked by the requester.

### Finding Description
In `do_ckd_coordinator`, the coordinator receives `CKDOutput` values from every other participant and adds them directly into the running sums:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each participant is supposed to compute:
- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

as shown in `compute_signature_share`: [2](#0-1) 

There is no proof-of-knowledge, Pedersen commitment, or any other mechanism attached to the transmitted `(norm_big_y, norm_big_c)` pair that would let the coordinator verify the values were honestly derived from the participant's actual key share `x_i` and a fresh blinding scalar `y_i`. The coordinator simply deserializes and accumulates whatever group elements arrive over the channel.

Compare this with the DKG protocol, which requires every participant to attach a Schnorr proof-of-knowledge to their polynomial commitment before any share is accepted: [3](#0-2) [4](#0-3) 

No equivalent validation exists in the CKD round.

### Impact Explanation
The final `CKDOutput` satisfies `unmask(app_sk) = big_c_total − app_sk · big_y_total`. When all participants are honest this equals `msk · H(pk ‖ app_id)`. If one participant substitutes arbitrary elements `big_y' ≠ λ_i · y_i · G` and `big_c' ≠ λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`, the coordinator's accumulated sums are shifted by attacker-chosen offsets, and `unmask` returns a value that is not `msk · H(pk ‖ app_id)`. The requester silently accepts a wrong confidential key with no indication of failure.

This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable or inconsistent cryptographic outputs.**

### Likelihood Explanation
Any participant in the CKD session is an unprivileged library caller who controls the bytes they send. The attack requires no special privilege, no leaked key material, and no cryptographic break — only the ability to serialize and transmit two arbitrary G1 points instead of the honestly computed ones. The `recv_from_others` helper performs no application-level validation beyond deserialization: [1](#0-0) 

A single colluding participant out of the full participant set is sufficient to corrupt the output.

### Recommendation
Require each participant to attach a non-interactive zero-knowledge proof of correct computation alongside `(norm_big_y, norm_big_c)`. Concretely, a sigma protocol (or Fiat-Shamir transform) can prove knowledge of `(y_i, x_i)` such that:
- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

with `x_i` consistent with the public polynomial commitment established during DKG. The coordinator must verify every such proof before adding the contribution to the running sums, mirroring the proof-of-knowledge verification already performed in `do_keyshare`: [4](#0-3) 

### Proof of Concept
1. Run a CKD session with `n ≥ 2` participants, one of which is malicious.
2. The malicious participant intercepts the call to `do_ckd_participant` and, instead of invoking `compute_signature_share`, constructs a `CKDOutput` containing two arbitrary non-identity G1 points `(P, Q)`.
3. It sends `(P, Q)` to the coordinator via `chan.send_private`.
4. The coordinator executes the loop at lines 50-55 and adds `P` to `norm_big_y` and `Q` to `norm_big_c` without any check.
5. The resulting `CKDOutput` is returned to the requester.
6. The requester calls `unmask(app_sk)` and obtains `Q − app_sk · P`, which is not `msk · H(pk ‖ app_id)`.
7. The requester silently uses the wrong key; no error is raised anywhere in the protocol. [5](#0-4)

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
