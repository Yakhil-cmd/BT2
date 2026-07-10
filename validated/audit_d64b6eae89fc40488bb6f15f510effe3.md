### Title
Malicious CKD Participant Corrupts Coordinator's Confidential Derived Key Output via Unverified Share Aggregation - (File: src/confidential_key_derivation/protocol.rs)

### Summary
A malicious participant in the Confidential Key Derivation (CKD) protocol can send arbitrary group elements to the coordinator instead of correctly computed shares. Because the coordinator performs no proof-of-correct-computation check before aggregating, the resulting `CKDOutput` is silently corrupted, causing every honest consumer of the derived key to receive an incorrect value.

### Finding Description
The CKD coordinator function `do_ckd_coordinator` collects one `(norm_big_y, norm_big_c)` tuple from every other participant and unconditionally adds them to its own running totals:

```rust
// src/confidential_key_derivation/protocol.rs  lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

No zero-value check, range check, or zero-knowledge proof of correct computation is performed on the received values. The participant side (`do_ckd_participant`) likewise attaches no proof to its message:

```rust
// src/confidential_key_derivation/protocol.rs  lines 29-31
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
Ok(None)
``` [2](#0-1) 

The correct share that participant `i` should send is:

- `norm_big_y_i = λ_i · y_i · G`
- `norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

computed inside `compute_signature_share`: [3](#0-2) 

A malicious participant can instead send any pair `(Δ_Y, Δ_C)` of its choosing. The coordinator then outputs:

- `Y' = Y_correct + Δ_Y`
- `C' = C_correct + Δ_C`

When the application unmasks with `app_sk`: `C' − app_sk · Y' = msk · H(pk ‖ app_id) + (Δ_C − app_sk · Δ_Y)`, which is wrong for any `(Δ_Y, Δ_C)` pair the attacker chooses (since the attacker does not know `app_sk`). The coordinator has no way to detect the manipulation.

### Impact Explanation
The coordinator is the sole party that receives `CKDOutputOption = Some(ckd_output)`. All downstream consumers of the confidential derived key rely on this single output. A single malicious participant can silently corrupt it, causing every honest party that uses the derived key to operate on an incorrect value. This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

### Likelihood Explanation
Any one of the `N − 1` non-coordinator participants can mount this attack. No special privilege, leaked key, or external assumption is required — only the ability to send a message during the normal protocol round. The attack is single-round, requires no timing or frontrunning, and is undetectable by the coordinator with the current code.

### Recommendation
Require each participant to accompany its `(norm_big_y, norm_big_c)` with a non-interactive zero-knowledge proof of correct formation — specifically a proof that:

1. `norm_big_y = λ_i · y_i · G` for some scalar `y_i` (a Schnorr proof of discrete log).
2. `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)` is a valid ElGamal ciphertext under the participant's committed public share `λ_i · x_i · G2` (a Chaum–Pedersen / DLEQ proof).

The coordinator must verify all proofs before aggregating. This is the standard approach used in threshold ElGamal decryption protocols (e.g., Pedersen's DKG-based threshold decryption).

### Proof of Concept

**Setup**: 3 participants `{P1, P2, P3}`, coordinator = `P1`, honest `P2`, malicious `P3`.

**Attack**:
1. `P3` runs `ckd(...)` normally up to the point of sending its share.
2. Instead of sending the correctly computed `(norm_big_y_3, norm_big_c_3)`, `P3` sends `(G, G)` (the generator point for both components).
3. `P1` (coordinator) receives `(norm_big_y_2, norm_big_c_2)` from `P2` (correct) and `(G, G)` from `P3` (malicious).
4. `P1` computes:
   - `Y' = norm_big_y_1 + norm_big_y_2 + G`
   - `C' = norm_big_c_1 + norm_big_c_2 + G`
5. `P1` returns `CKDOutput::new(Y', C')` — a silently corrupted output.
6. The application calls `ckd_output.unmask(app_sk)` and obtains `msk · H(pk ‖ app_id) + G − app_sk · G`, which is not the correct confidential derived key.

No error is raised anywhere in the protocol. The corruption is silent and undetectable by the coordinator. [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-32)
```rust
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
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
