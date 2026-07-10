### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator blindly aggregates each participant's `(norm_big_y, norm_big_c)` contribution with no proof of correct computation. Any single malicious participant can substitute arbitrary group elements, causing the coordinator to derive a permanently wrong confidential key with no ability to detect or attribute the fault.

### Finding Description
In `do_ckd_coordinator` (lines 35–57 of `src/confidential_key_derivation/protocol.rs`), the coordinator receives each participant's `CKDOutput` and unconditionally adds the two group elements together:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

The correct contribution from participant `i` is:

- `norm_big_y_i = λ_i · y_i · G`
- `norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

as computed in `compute_signature_share` (lines 148–181). There is no commitment, no zero-knowledge proof, and no consistency check that the received `(norm_big_y, norm_big_c)` pair was produced from a valid signing share and a matching randomness `y_i`. The protocol sends these values privately to the coordinator (line 30 in `do_ckd_participant`) and the coordinator has no way to verify them.

The correct final output satisfies:

```
C − app_sk · Y = msk · H(pk ‖ app_id)   (the confidential key)
```

If participant `j` sends `(norm_big_y_j', norm_big_c_j')` instead of the correct values, the coordinator computes:

```
Y'  = Y_correct + Δ_y
C'  = C_correct + Δ_c
```

and unmasks to `msk · H(pk ‖ app_id) + Δ_c − app_sk · Δ_y`, which is an unpredictable, wrong value. The coordinator has no way to detect the corruption or identify the culprit.

### Impact Explanation
A single malicious participant causes the coordinator to derive an incorrect, unusable confidential key. Because the CKD output is the sole product of the protocol and there is no threshold reconstruction or redundancy check, one bad actor is sufficient to permanently corrupt the result for all honest parties. This maps directly to the allowed High impact: *Corruption of CKD outputs so honest parties accept unusable cryptographic outputs*.

### Likelihood Explanation
Any participant in the CKD protocol can trivially mount this attack by sending arbitrary G1 points. No cryptographic capability is required beyond participation in the protocol. The attack is undetectable and unattributable without additional verification mechanisms.

### Recommendation
Add a zero-knowledge proof of correct computation to each participant's contribution. Specifically, each participant should prove in zero-knowledge that:

1. `norm_big_y_i = λ_i · y_i · G` for some scalar `y_i`, and
2. `norm_big_c_i = λ_i · x_i · H(pk ‖ app_id) + λ_i · y_i · app_pk`

using a discrete-log equality proof (a `dlogeq`-style proof, already present in `src/crypto/proofs/dlogeq.rs`) that the same `y_i` was used in both `norm_big_y_i` and the `app_pk`-scaled term of `norm_big_c_i`, and a separate proof binding `norm_big_c_i` to the participant's committed signing share. The coordinator must verify all proofs before aggregating.

### Proof of Concept

A malicious participant `j` replaces their honest contribution with arbitrary points:

```rust
// Honest path (compute_signature_share):
let norm_big_y = big_y * lambda_i;          // λ_j · y_j · G
let norm_big_c = big_c * lambda_i;          // λ_j · (x_j·H + y_j·app_pk)

// Malicious path — participant sends garbage instead:
let norm_big_y_malicious = ElementG1::generator();   // just G
let norm_big_c_malicious = ElementG1::generator();   // just G
chan.send_private(waitpoint, coordinator, &(norm_big_y_malicious, norm_big_c_malicious))?;
```

The coordinator at lines 50–55 adds these unchecked values:

```rust
norm_big_y += participant_output.big_y();   // adds G instead of λ_j·y_j·G
norm_big_c += participant_output.big_c();   // adds G instead of λ_j·(x_j·H+y_j·app_pk)
```

The resulting `ckd_output` is corrupted. When the coordinator calls `ckd_output.unmask(app_sk)`, the result is `msk · H(pk ‖ app_id) + G − app_sk · G`, which is not the intended confidential key and is cryptographically unrelated to it. No error is raised and no participant is identified as malicious.