Looking at the CKD protocol in `src/confidential_key_derivation/protocol.rs`, I can identify a clear analog to the "missing validation checks" vulnerability class.

In `do_ckd_coordinator` (lines 35–58), the coordinator receives `(big_y, big_c)` shares from every participant and blindly sums them with no proof-of-correctness verification:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

Any single malicious participant can send arbitrary group elements for `big_y` and `big_c`, and the coordinator will incorporate them into the final CKD output without any check. This is the direct analog to the ADL report's "minimum output amount is set to zero / any price is allowed" — the protocol imposes no bounds or validity constraints on what it accepts from participants.

---

### Title
Missing Proof-of-Correctness on CKD Participant Shares Allows Malicious Participant to Corrupt Derived Confidential Key — (`File: src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator aggregates ElGamal share contributions `(big_y, big_c)` from all participants with no zero-knowledge proof or consistency check. A single malicious participant can submit arbitrary group elements, silently corrupting the final `CKDOutput` that honest parties accept.

### Finding Description
`compute_signature_share` produces a normalized ElGamal pair `(λ_i · y_i · G, λ_i · (x_i · H(pk‖app_id) + y_i · app_pk))`. The coordinator in `do_ckd_coordinator` receives these pairs over the channel and adds them directly:

```rust
norm_big_y += participant_output.big_y();
norm_big_c += participant_output.big_c();
``` [1](#0-0) 

There is no check that:
- `big_y` is a valid, non-identity group element on the correct curve.
- `big_c` is consistent with `big_y` and the participant's committed public key share.
- Any discrete-log relationship holds between `big_y` and `big_c` (e.g., a Chaum-Pedersen or ElGamal proof of knowledge).

The `compute_signature_share` function itself is never called on the received data — only on the local participant's own data. [2](#0-1) 

### Impact Explanation
The final `CKDOutput` is `(Y, C)` where `C − app_sk · Y` should equal `msk · H(pk‖app_id)`. A malicious participant who sends `(big_y′, big_c′)` instead of their correct share shifts both `Y` and `C` by arbitrary amounts. The coordinator returns this corrupted `CKDOutput` as `Some(ckd_output)`, and honest parties have no way to detect the corruption. The derived confidential key is therefore wrong, and any application relying on it (e.g., a TEE) will silently operate on an incorrect secret.

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation
- Any single participant in the protocol can trigger this; no threshold of colluders is required.
- The attack requires only sending two arbitrary group elements instead of the correctly computed ones — trivial to implement.
- There is no post-protocol verification step that would catch the corruption before the output is used.

### Recommendation
Require each participant to accompany their `(big_y, big_c)` share with a Chaum-Pedersen proof of discrete-log equality (or an equivalent ElGamal proof of knowledge), proving that `big_c − big_y · (app_pk / G) = x_i · H(pk‖app_id)` without revealing `x_i`. The coordinator must verify each proof before adding the share to the running sum. This is analogous to introducing `MAX_POSITION_IMPACT_FACTOR_FOR_ADL` — a hard bound that prevents unchecked contributions from distorting the final output.

### Proof of Concept
1. Honest participants run `ckd(...)` normally.
2. Malicious participant `P_m` intercepts the send step in `do_ckd_participant` and instead sends `(G, G)` (the generator point for both fields) to the coordinator.
3. The coordinator executes:
   ```rust
   norm_big_y += G;   // adds arbitrary point
   norm_big_c += G;   // adds arbitrary point
   ```
4. The returned `CKDOutput` satisfies `C − app_sk · Y ≠ msk · H(pk‖app_id)`.
5. Any application calling `ckd_output.unmask(app_sk)` receives a wrong key with no error. [3](#0-2)

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
