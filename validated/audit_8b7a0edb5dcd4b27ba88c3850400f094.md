### Title
Malicious CKD Participant Can Submit Unchecked `CKDOutput` to Corrupt the Coordinator's Confidential Derived Key — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

In the Confidential Key Derivation (CKD) protocol, the coordinator aggregates `CKDOutput` shares received from participants by blindly summing their `big_y` and `big_c` components. There is no zero-knowledge proof, commitment, or any other binding check that each participant's share was computed using the agreed-upon `app_id` and `app_pk`. A single malicious participant can substitute an arbitrarily crafted `CKDOutput` — analogous to the spoofed `extraData` stack in the external report — and the coordinator will silently incorporate it, producing a corrupted confidential derived key that honest parties accept as valid.

---

### Finding Description

In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 35–57), the coordinator collects each participant's `(norm_big_y, norm_big_c)` pair and accumulates them:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

The correct per-participant computation (lines 148–181) is:

```
hash_point = H(pk || app_id)
big_s      = hash_point * x_i          // x_i = private share
big_c      = big_s + app_pk * y        // y = fresh random scalar
big_y      = y * G
norm_big_y = λ_i · big_y
norm_big_c = λ_i · big_c
```

The coordinator has no way to verify that the received `norm_big_c` was formed using the session's `app_id` and `app_pk`. There is no accompanying proof of knowledge (e.g., a Sigma protocol showing `big_c = H(pk||app_id)·x_i + app_pk·y` for the `y` committed in `big_y`), no hash commitment opened in a prior round, and no consistency check of any kind. The channel only authenticates *who* sent the message, not *what* was computed.

This is the direct analog of the external report: just as `validateOrder` only checked `stack.lien.token` but not `collateralId`, `do_ckd_coordinator` only checks that the message arrived from a legitimate participant, but not that the participant's share was computed for the correct `(app_id, app_pk)` context.

---

### Impact Explanation

A malicious participant can send any `(norm_big_y', norm_big_c')` — e.g., values computed for a different `app_id'`, or entirely random group elements. The coordinator sums these into the final `CKDOutput`. When the application calls `ckd_output.unmask(app_sk)`, it obtains:

```
unmask = Σ norm_big_c_i - app_sk · Σ norm_big_y_i
```

With the malicious contribution substituted, this no longer equals `H(pk || app_id) · msk`. Honest parties receive and accept a `CKDOutput` that decrypts to a wrong or unpredictable confidential key. The corruption is undetectable at the protocol level because no honest party knows the expected output in advance.

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable or inconsistent cryptographic outputs.**

---

### Likelihood Explanation

Any single compromised or malicious threshold participant can mount this attack unilaterally. The attack requires no special privilege beyond holding a valid key share and participating in a CKD session. The `app_id` and `app_pk` are public inputs, so the attacker knows exactly what the honest computation should look like and can craft a deviation that is indistinguishable to the coordinator. The protocol has no abort or blame mechanism for this case.

---

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof binding the share to the session's public parameters. Concretely, a Sigma protocol (or Fiat-Shamir transform) should prove:

> "I know `y` and `x_i` such that `norm_big_y = λ_i · y · G` and `norm_big_c = λ_i · (H(pk||app_id) · x_i + app_pk · y)`"

where `H(pk||app_id)` and `app_pk` are fixed public inputs for the session, and `x_i` is bound to the participant's public verification share from DKG. The coordinator must verify this proof before incorporating any participant's contribution. Without this, the aggregation step provides no cryptographic guarantee about the correctness of the inputs.

---

### Proof of Concept

1. An honest set of participants runs CKD for `app_id = "app_A"` and `app_pk = A`.
2. Malicious participant `P_m` computes `(norm_big_y', norm_big_c')` using `app_id' = "app_B"` (or random scalars) instead of the session parameters.
3. `P_m` sends this spoofed `CKDOutput` to the coordinator via the normal protocol channel.
4. `do_ckd_coordinator` (lines 50–55) adds `norm_big_y'` and `norm_big_c'` into the running sum without any check.
5. The coordinator outputs `CKDOutput::new(corrupted_big_y, corrupted_big_c)`.
6. The application calls `ckd_output.unmask(app_sk)` and obtains a value that is not `H(pk || app_id) · msk`, silently accepting a corrupted confidential derived key. [1](#0-0) [2](#0-1)

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
