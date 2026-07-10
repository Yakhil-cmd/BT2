### Title
Missing `app_id` Context Binding Validation in CKD Coordinator Allows Malicious Participant to Corrupt Derived Key Output - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly aggregates participant share contributions without any proof that each participant used the correct `app_id` and `app_pk`. A malicious participant can send shares computed under a different `app_id` (or entirely arbitrary group elements), and the coordinator will silently incorporate them, producing a corrupted CKD output that does not correspond to any valid confidential key derivation.

---

### Finding Description

In `do_ckd_coordinator` (lines 35–57 of `src/confidential_key_derivation/protocol.rs`), the coordinator collects `CKDOutput` values from every participant and sums them:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

Each participant is supposed to compute their share in `compute_signature_share` (lines 148–182) as:

```
hash_point = H(pk || app_id)
big_s      = hash_point * private_share_i
big_c      = big_s + app_pk * y_i
big_y      = G * y_i
```

The coordinator has no mechanism to verify that a participant actually used the agreed-upon `app_id`, the correct `app_pk`, or even their real private share. No zero-knowledge proof, commitment, or cross-check is attached to the `CKDOutput` message. The `CKDOutput` type is a plain container of two group elements with no binding to any context.

This is the direct analog of the missing chain-ID validation in the external report: `app_id` is the context identifier that uniquely scopes a CKD derivation (just as `chain_id` scopes a transaction to a specific network), and it is never validated on the receiving side. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

**High — Corruption of CKD output.**

When a malicious participant sends `(big_y', big_c')` computed under a different `app_id'` (or arbitrary values), the coordinator sums all contributions and produces a `CKDOutput` that does not equal `msk · H(pk ‖ app_id)`. Every honest party that later tries to use this output (e.g., to unmask a confidential key for the intended application) will obtain a wrong result. The output is cryptographically indistinguishable from a valid one to the coordinator, so the corruption is silent and accepted.

This matches the allowed impact: *"Corruption of … CKD outputs so honest parties accept … unusable cryptographic outputs."* [3](#0-2) 

---

### Likelihood Explanation

**High.** Any single participant in the protocol can trigger this. The attacker only needs to call `ckd()` with a different `app_id` (or send hand-crafted group elements over the channel). No special cryptographic capability is required. The coordinator has no way to detect the substitution because no proof of correct computation is transmitted. [4](#0-3) 

---

### Recommendation

Attach a zero-knowledge proof of correct share computation to each participant's `CKDOutput`. Concretely, each participant should prove in zero knowledge that:

1. `big_c = hash_point * x_i + app_pk * y_i` for the agreed `hash_point = H(pk ‖ app_id)` and `app_pk`, and
2. `big_y = G * y_i`

using a Chaum-Pedersen or Maurer-style NIZK (the library already has the Maurer proof infrastructure in `src/crypto/`). The coordinator must verify these proofs before summing contributions. This binds every share to the correct `app_id` context, directly mirroring the chain-ID assertion in the external report's patch. [1](#0-0) 

---

### Proof of Concept

1. Honest participants `P_1, …, P_{n-1}` call `ckd(…, app_id_correct, app_pk, …)`.
2. Malicious participant `P_n` calls `ckd(…, app_id_attacker, app_pk, …)` where `app_id_attacker ≠ app_id_correct`, or directly injects arbitrary `(big_y', big_c')` via the channel.
3. `do_ckd_participant` for `P_n` computes `hash_point' = H(pk ‖ app_id_attacker)` and sends `(lambda_n * big_y', lambda_n * big_c')` to the coordinator.
4. `do_ckd_coordinator` receives all shares and sums them without any validation:
   ```
   norm_big_c = Σ_{i=1}^{n-1} lambda_i * C_i(correct) + lambda_n * C_n(attacker)
   ```
5. The resulting `CKDOutput` does not equal `msk · H(pk ‖ app_id_correct)`. The coordinator returns this corrupted output as `Some(ckd_output)`, and any downstream consumer (e.g., a TEE application) that calls `ckd_output.unmask(app_sk)` obtains a wrong key with no error signal. [5](#0-4) [2](#0-1)

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
