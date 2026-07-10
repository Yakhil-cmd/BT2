### Title
Unverified Participant Contributions in CKD Protocol Allow Malicious Participant to Corrupt Derived Key Output - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator aggregates participant contributions `(norm_big_y, norm_big_c)` by direct summation with no cryptographic verification that each participant used their actual secret share. A single malicious participant can inject arbitrary group elements, causing the coordinator to accept and output a corrupted CKD result that does not correspond to `msk · H(pk ∥ app_id)`.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `CKDOutput` and unconditionally adds the components together: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

Each honest participant is supposed to compute: [2](#0-1) 

```
big_y  = y_i · G₁
big_s  = x_i · H(pk ∥ app_id)
big_c  = big_s + y_i · app_pk
norm_big_y = λ_i · big_y
norm_big_c = λ_i · big_c
```

where `x_i` is the participant's secret share from DKG and `y_i` is a fresh random scalar. The protocol's correctness depends entirely on every participant using their genuine `x_i`. However, **no proof of knowledge, commitment, or pairing-based check is performed** on the received `(norm_big_y, norm_big_c)` pair before it is added into the running sum.

A malicious participant `P_m` can instead send any pair `(Y', C')` of their choosing. Because the coordinator has no way to distinguish a correctly-formed contribution from an arbitrary one, the final `CKDOutput` becomes:

```
norm_big_y_total = (sum of honest λ_i · y_i · G₁) + Y'
norm_big_c_total = (sum of honest λ_i · (x_i · H + y_i · app_pk)) + C'
```

When the application unmasks the output with `app_sk`, the recovered confidential key is no longer `msk · H(pk ∥ app_id)` — it is a corrupted, attacker-influenced value.

The protocol requires **all** N participants to contribute (the coordinator calls `recv_from_others` which waits for every other participant), so a single malicious participant is sufficient to corrupt the output. [3](#0-2) 

---

### Impact Explanation

A malicious participant can cause the coordinator — and any downstream consumer of the `CKDOutput` — to accept a cryptographically invalid derived key. The unmasked confidential key will not equal `msk · H(pk ∥ app_id)`, silently breaking the intended key derivation. This matches the allowed impact:

> **High: Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

There is no error returned, no detection, and no way for the coordinator to distinguish a corrupted output from a legitimate one.

---

### Likelihood Explanation

Any participant enrolled in a CKD session is a valid attacker. The attack requires only sending two arbitrary G1 elements in place of the honest contribution — no cryptographic capability beyond participation is needed. The protocol provides zero resistance: there is no commitment round, no ZK proof, and no pairing check. Likelihood is **high**.

---

### Recommendation

Add a pairing-based verification step in the coordinator before accepting each participant's contribution. Each participant should additionally send their raw BLS signature share `big_s_i = x_i · H(pk ∥ app_id)` (in G1), and the coordinator should verify:

```
e(big_s_i, G₂) == e(H(pk ∥ app_id), X_i)
```

where `X_i = x_i · G₂` is the participant's public verification share from DKG output. The coordinator then checks `big_c_i - big_s_i` is consistent with `big_y_i` and `app_pk` via a discrete-log equality proof (standard Sigma protocol over two G1 bases). Only contributions that pass both checks should be summed into the final `CKDOutput`.

---

### Proof of Concept

1. Honest participants run DKG to obtain shares `x_i` and master public key `pk`.
2. A CKD session is initiated with `app_id` and `app_pk`.
3. Malicious participant `P_m` intercepts the protocol and, instead of computing `compute_signature_share`, sends:
   - `norm_big_y = ElementG1::identity()` (or any arbitrary point)
   - `norm_big_c = ElementG1::generator() * attacker_scalar` (arbitrary)
4. The coordinator at `do_ckd_coordinator` lines 50–55 adds these values without verification.
5. The resulting `CKDOutput` satisfies `ckd_output.unmask(app_sk) ≠ msk · H(pk ∥ app_id)`.
6. The coordinator returns `Ok(Some(ckd_output))` — no error is raised. [4](#0-3)

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
