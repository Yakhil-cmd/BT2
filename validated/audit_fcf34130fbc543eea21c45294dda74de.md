### Title
Missing Proof-of-Correctness Verification for Participant Shares in CKD Protocol Allows Malicious Participant to Corrupt Confidential Derived Key Output - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary

The `do_ckd_coordinator` function in the Confidential Key Derivation (CKD) protocol blindly accumulates `(norm_big_y, norm_big_c)` values sent by participants without any cryptographic proof that those values were computed correctly from the participant's actual key share. A single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that unmasks to a wrong confidential derived key. This is the direct analog of the missing slippage protection in `LendingPool.deposit()`: in both cases, an intermediate value contributed by an untrusted party is consumed without validation, silently corrupting the final output.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `(norm_big_y, norm_big_c)` and sums them unconditionally: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

The correct values that participant `i` must send are:

- `norm_big_y_i = λ_i · y_i · G`
- `norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

where `x_i` is the participant's secret key share and `y_i` is a fresh random blinding scalar. These are computed locally in `compute_signature_share`: [2](#0-1) 

However, the coordinator performs **no verification** that the received `(norm_big_y, norm_big_c)` satisfies any relation to the participant's committed public key share. There is no Sigma proof, no Pedersen commitment check, and no consistency check against the public key material established during DKG.

A malicious participant `j` can instead send arbitrary `(norm_big_y_j', norm_big_c_j')`. The coordinator then computes:

```
big_y_total'  = big_y_total  - norm_big_y_j  + norm_big_y_j'
big_c_total'  = big_c_total  - norm_big_c_j  + norm_big_c_j'
```

The TEE unmasks via `big_c_total' - app_sk · big_y_total'`, which no longer equals `msk · H(pk ‖ app_id)`. The derived confidential key is silently corrupted. [3](#0-2) 

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The coordinator outputs a `CKDOutput` whose `unmask(app_sk)` value is an arbitrary, attacker-influenced group element rather than the correct `msk · H(pk ‖ app_id)`. Any TEE or downstream consumer that relies on this output to derive a secret will silently receive a wrong key. Because `app_sk` is not known to the attacker, they cannot steer the output to a specific chosen key (ruling out Critical), but they can guarantee the output is wrong, permanently denying the correct confidential derived key to all honest parties for that invocation.

---

### Likelihood Explanation

Any participant in the CKD protocol can trigger this. The attacker role is a **malicious normal participant** — no privileged access is required. The participant simply deviates from the protocol by sending crafted `(big_y, big_c)` values in the single private message to the coordinator. There is no retry or recovery mechanism in the protocol; a single corrupted invocation produces a permanently wrong output.

---

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct construction. Concretely, a participant must prove in zero knowledge that:

1. They know `y_i` such that `norm_big_y_i = λ_i · y_i · G`.
2. They know `x_i` (consistent with their DKG public key share `X_i = x_i · G_2`) such that `norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`.

A standard approach is a Chaum–Pedersen / DLEQ proof binding `norm_big_c_i - λ_i · x_i · H(pk ‖ app_id)` to `norm_big_y_i` via the shared discrete-log relation with `app_pk` and `G`. The coordinator must verify all such proofs before accumulating the shares, rejecting and aborting if any proof fails.

---

### Proof of Concept

**Setup:** 3 participants, threshold 2. Participant 3 is malicious.

1. Participants 1 and 2 run `compute_signature_share` honestly and send correct `(norm_big_y_i, norm_big_c_i)` to the coordinator.
2. Participant 3 (malicious) sends `(ElementG1::identity(), ElementG1::identity())` — the identity element — instead of its correct share.
3. The coordinator at `do_ckd_coordinator` sums all three contributions:
   - `norm_big_y_total = norm_big_y_1 + norm_big_y_2 + identity`
   - `norm_big_c_total = norm_big_c_1 + norm_big_c_2 + identity`
4. The resulting `CKDOutput::unmask(app_sk)` equals `(norm_big_c_1 + norm_big_c_2) - app_sk · (norm_big_y_1 + norm_big_y_2)`, which is missing participant 3's contribution and therefore does **not** equal `msk · H(pk ‖ app_id)`.
5. The test assertion `assert_eq!(confidential_key, expected_confidential_key)` from the existing test at line 278 would fail, confirming the corruption. [4](#0-3)

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
