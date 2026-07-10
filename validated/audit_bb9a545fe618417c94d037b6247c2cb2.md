### Title
CKD Coordinator Aggregates Participant Shares Without Proof of Correct Computation, Enabling Malicious Corruption of Derived Confidential Key - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator in `do_ckd_coordinator` blindly aggregates `(norm_big_y, norm_big_c)` group-element pairs received from participants with no zero-knowledge proof or commitment binding those values to the participant's actual secret share. Any single malicious participant can substitute arbitrary group elements, causing the coordinator to produce a permanently corrupted `CKDOutput` that honest parties accept as valid. This is a direct analog to the ERC20 fee-on-transfer pattern: the protocol assumes received values equal the correctly-computed values, but a non-conforming sender breaks that assumption silently.

---

### Finding Description

**Root cause — no verification of participant shares in `do_ckd_coordinator`**

Each honest participant is supposed to compute and send:

```
norm_big_y = λ_i · y_i · G          (random blinding commitment)
norm_big_c = λ_i · (x_i · H(pk, app_id) + y_i · app_pk)   (masked key share)
```

as implemented in `compute_signature_share`: [1](#0-0) 

The coordinator receives these pairs and sums them unconditionally: [2](#0-1) 

There is no proof that `norm_big_y` is of the form `λ_i · y · G` for any scalar `y`, and no proof that `norm_big_c` encodes the participant's actual secret share `x_i`. The only check performed is implicit deserialization (confirming the bytes represent a valid curve point), which is entirely insufficient.

**Exploit path**

A malicious participant `P_m` replaces its honest output with arbitrary group elements `(Δ_Y, Δ_C)` before sending to the coordinator. The coordinator computes:

```
Y_final   = Y_honest_sum + Δ_Y
C_final   = C_honest_sum + Δ_C
```

When the application calls `unmask(app_sk)`:

```
C_final - app_sk · Y_final
  = msk · H(pk, app_id)  +  (Δ_C - app_sk · Δ_Y)
```

The term `(Δ_C - app_sk · Δ_Y)` is an attacker-controlled additive offset (the attacker does not need to know `app_sk` to make this non-zero; choosing `Δ_Y = 0, Δ_C = arbitrary_nonzero` suffices). The resulting confidential key is silently wrong, and the coordinator returns it as `Some(ckd_output)` with no error.

**Comparison to the ERC20 analog**

| ERC20 (PayoutManager) | CKD (threshold-signatures) |
|---|---|
| Assumes `safeTransferFrom` delivers exactly `cc.amount` | Assumes each participant delivers correctly-computed `(norm_big_y, norm_big_c)` |
| Fee-on-transfer token silently delivers less | Malicious participant silently delivers wrong group elements |
| Deal tokens minted from nominal amount, not actual received amount | Confidential key derived from corrupted aggregate, not honest shares |
| No post-transfer balance check | No proof-of-correct-computation on received shares | [3](#0-2) 

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept an incorrect derived confidential key.**

A single malicious participant causes the coordinator to output a `CKDOutput` whose `unmask` result is `msk · H(pk, app_id) + attacker_offset` instead of `msk · H(pk, app_id)`. Every honest party (coordinator and all downstream consumers) accepts this corrupted value as the legitimate confidential derived key. The correct key is permanently unrecoverable from this protocol run without re-running the entire CKD session.

---

### Likelihood Explanation

Any participant in a CKD session can trigger this. No privileged access, no leaked keys, and no cryptographic break is required. The attacker simply deviates from `compute_signature_share` and sends `(ElementG1::identity(), arbitrary_nonzero_point)` or any other pair. The protocol has a single round of communication from participants to coordinator with no challenge-response, making detection impossible within the protocol itself.

---

### Recommendation

Add a non-interactive zero-knowledge proof of correct computation alongside each `(norm_big_y, norm_big_c)` share. Concretely, each participant should prove in zero-knowledge that:

1. `norm_big_y = λ_i · y · G` for some scalar `y` (a Schnorr proof of discrete log suffices).
2. `norm_big_c - norm_big_y · (app_pk / G) = λ_i · x_i · H(pk, app_id)` — i.e., the masked share is consistent with the participant's public verification share `λ_i · x_i · G` (derivable from the DKG output).

The coordinator must verify all proofs before aggregating. Alternatively, use a commit-then-reveal scheme so that participants are bound to their values before seeing others' contributions, and abort if any commitment fails to open correctly.

---

### Proof of Concept

```
Setup:
  participants = [P0 (coordinator), P1 (honest), P2 (malicious)]
  All participants complete DKG; master secret key msk = x0 + x1 + x2 (Lagrange-weighted)
  app_id, app_pk = app_sk · G are fixed

Attack:
  P2 computes compute_signature_share() correctly but discards the result.
  P2 instead sends to coordinator:
      norm_big_y = ElementG1::identity()   (zero element)
      norm_big_c = ElementG1::generator()  (arbitrary nonzero point ≠ correct value)

Coordinator aggregates:
  Y_final = (λ0·y0 + λ1·y1)·G + 0
  C_final = (λ0·C0 + λ1·C1) + G

unmask(app_sk):
  C_final - app_sk · Y_final
  = msk · H(pk, app_id) + G   ← wrong by exactly one generator point

Result:
  Coordinator returns CKDOutput containing the corrupted key.
  No error is raised. Honest parties accept the output.
  The correct confidential key msk · H(pk, app_id) is unrecoverable from this run.
``` [2](#0-1) [1](#0-0)

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
