### Title
Malicious Participant Can Corrupt CKD Aggregate Without Detection — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

The Confidential Key Derivation (CKD) coordinator aggregates per-participant shares by blindly summing them with no cryptographic verification. A single malicious participant can send arbitrary `(big_y, big_c)` values, corrupting the final CKD output accepted by all honest parties. This is structurally identical to the oracle report's root cause: a system designed to aggregate multiple independent inputs collapses them into a single value without cross-validating each contributor, so one bad actor defeats the entire multi-party resilience.

---

### Finding Description

In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 35–57), the coordinator receives a `(norm_big_y, norm_big_c)` pair from every other participant and unconditionally adds each pair to a running sum:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

Each honest participant is supposed to compute, in `compute_signature_share`:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk, app_id) + y_i · app_pk)
``` [2](#0-1) 

The coordinator never verifies that the received `(big_y_i, big_c_i)` satisfies this relationship. No zero-knowledge proof, no pairing check, and no consistency check against the participant's public key share is performed before the values are added to the aggregate.

A malicious participant `m` can instead send any pair `(big_y_m, big_c_m)` of its choosing. Because the coordinator simply sums all contributions:

```
final_big_c = Σ_{i≠m} norm_big_c_i  +  big_c_m   (malicious)
final_big_y = Σ_{i≠m} norm_big_y_i  +  big_y_m   (malicious)
```

The `unmask(app_sk)` call then computes `final_big_c − app_sk · final_big_y`, which equals:

```
msk · H(pk, app_id)  +  (big_c_m − app_sk · big_y_m)
```

The additive term `(big_c_m − app_sk · big_y_m)` is fully under the malicious participant's control (they choose `big_y_m` and `big_c_m` freely), so the derived confidential key is shifted by an attacker-chosen offset. Honest parties have no way to detect this; they receive and accept the corrupted `CKDOutput` as legitimate.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept incorrect cryptographic outputs.**

The final `CKDOutput` is the sole product of the CKD protocol. Any downstream consumer (e.g., a TEE application) that calls `unmask(app_sk)` will obtain a wrong confidential key. Because the corruption is additive and attacker-controlled, the malicious participant can steer the derived key to any target in the group, making the output cryptographically useless or predictable to the attacker. All honest participants accept this output without error.

---

### Likelihood Explanation

Any participant in the CKD protocol is an unprivileged library caller who supplies their own `(big_y, big_c)` values. The attack requires no special privilege, no leaked key, and no external dependency. It is executable in a single protocol run by any one of the `n` participants. The only precondition is participation in the protocol, which is the normal operating condition.

---

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation — specifically, a proof that `norm_big_c_i` was computed as `λ_i · (x_i · H(pk, app_id) + y_i · app_pk)` for the same `y_i` used to produce `norm_big_y_i = λ_i · y_i · G`, and that `x_i` is consistent with the participant's committed public key share. The coordinator must verify all such proofs before adding any contribution to the aggregate. Alternatively, a verifiable encryption or Pedersen-commitment-based approach can bind each `big_c_i` to the participant's known public share, allowing the coordinator to reject malformed inputs.

---

### Proof of Concept

1. Honest participants `{P1, P2, P3}` run CKD with threshold 2-of-3. `P3` is malicious.
2. `P3` computes the correct `(norm_big_y_3, norm_big_c_3)` but instead sends `(G, G)` (the generator point for both fields) to the coordinator.
3. The coordinator executes:
   ```rust
   norm_big_y += participant_output.big_y();  // adds G instead of λ3·y3·G
   norm_big_c += participant_output.big_c();  // adds G instead of λ3·(x3·H+y3·app_pk)
   ``` [3](#0-2) 
4. The coordinator returns `CKDOutput::new(corrupted_big_y, corrupted_big_c)` with no error.
5. The application calls `ckd_output.unmask(app_sk)` and obtains `msk·H(pk,app_id) + (G − app_sk·G)`, which is not the intended confidential key. The protocol completes successfully from the honest parties' perspective, but the derived key is wrong.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L165-181)
```rust
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
