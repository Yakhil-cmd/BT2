### Title
Malicious Participant Can Corrupt CKD Output by Sending Unvalidated Arbitrary Elliptic Curve Points — (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

In the Confidential Key Derivation (CKD) protocol, the coordinator aggregates elliptic curve point contributions `(big_y, big_c)` from every participant with no cryptographic validation of correctness. A malicious participant can substitute arbitrary curve points for their honest contribution. The coordinator silently accumulates the poisoned values, producing a corrupted `CKDOutput` that honest parties accept without error, causing the derived confidential key to be wrong.

---

### Finding Description

The root cause is in `do_ckd_coordinator` in `src/confidential_key_derivation/protocol.rs`. After computing its own share, the coordinator loops over every other participant's message and unconditionally adds the received points to the running totals: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant is supposed to compute and send: [2](#0-1) 

```
norm_big_y = λ_i · y_i · G
norm_big_c = λ_i · (x_i · H(pk, app_id) + y_i · app_pk)
```

There is no zero-knowledge proof, no commitment-then-reveal, and no algebraic consistency check on the received `(big_y, big_c)` pair. The coordinator has no way to distinguish a correctly computed share from an arbitrary curve point. This is the direct analog of the Datatrust.vy bug: just as the Backend could report excess bytes that were accumulated into `bytes_purchased` without an upper-bound check, a malicious CKD participant can report arbitrary point values that are accumulated into the shared protocol state without any correctness check.

Contrast this with the OT-based ECDSA presign protocol, which explicitly verifies the aggregated shares against public commitments before proceeding: [3](#0-2) 

No equivalent guard exists in the CKD coordinator path.

---

### Impact Explanation

A malicious participant Eve sends `(big_y_evil, big_c_evil)` instead of her correct `(norm_big_y_eve, norm_big_c_eve)`. The coordinator computes:

```
final_big_y = Σ_{honest j} norm_big_y_j  +  big_y_evil
final_big_c = Σ_{honest j} norm_big_c_j  +  big_c_evil
```

The confidential key the TEE derives is:

```
key = final_big_c − app_sk · final_big_y
    = msk · H(pk, app_id)  +  (big_c_evil − app_sk · big_y_evil)
```

Unless `big_c_evil = app_sk · big_y_evil` (which Eve cannot arrange without knowing `app_sk`), the derived key is wrong. The coordinator returns the corrupted `CKDOutput` with `Ok(Some(...))` — no error is raised, no detection occurs, and honest parties accept the unusable key as valid output.

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.** [4](#0-3) 

---

### Likelihood Explanation

Any participant included in the `participants` list can execute this attack. No privileged role, leaked key, or external assumption is required. The attacker simply sends the identity point `(0, 0)` or any arbitrary curve point in place of their honest contribution. The protocol has a single round of communication from participants to coordinator, so the attack requires only one malformed message. The coordinator has no mechanism to identify the culprit or retry with a corrected participant set.

---

### Recommendation

- Add a Schnorr-style zero-knowledge proof of correct computation alongside each participant's `(norm_big_y, norm_big_c)` contribution, proving knowledge of `y_i` and `x_i` consistent with the public key and the committed points.
- Alternatively, use a commit-then-reveal scheme: participants first broadcast a hash commitment to their values, then open them; the coordinator verifies each opening before accumulating.
- At minimum, document that the CKD protocol assumes all participants are honest and enforce this at the API level (e.g., by requiring a threshold-based variant or restricting the participant set to TEE-attested nodes).

---

### Proof of Concept

1. Alice (coordinator), Bob, and Eve participate in `ckd(...)` for the same `app_id` and `app_pk`.
2. Eve's honest computation yields `(norm_big_y_eve, norm_big_c_eve)`.
3. Eve instead sends `(G, G)` — the generator point for both fields — to Alice via the private channel at `waitpoint`.
4. Alice's coordinator loop adds `G` to `norm_big_y` and `G` to `norm_big_c` without any check.
5. The final `CKDOutput` is offset by `(G − norm_big_y_eve, G − norm_big_c_eve)` relative to the correct value.
6. Alice returns `Ok(Some(ckd_output))` with the corrupted output; no `ProtocolError` is raised.
7. The TEE calls `ckd_output.unmask(app_sk)` and obtains a key that differs from `msk · H(pk, app_id)` by `G − app_sk · G = (1 − app_sk) · G`, which is a fixed, non-zero offset — the derived key is permanently wrong for this session. [5](#0-4)

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

**File:** src/confidential_key_derivation/protocol.rs (L176-181)
```rust
    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L160-168)
```rust
    // beta*G =?= X + B
    // Spec 2.5
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }
```
