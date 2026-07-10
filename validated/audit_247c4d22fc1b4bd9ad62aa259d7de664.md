### Title
Missing Verification of Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt Derived Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly aggregates `(big_y, big_c)` group elements received from participants with no proof-of-knowledge or commitment check. A single malicious participant can send arbitrary curve points, causing the coordinator to output a silently corrupted confidential key that honest parties accept as valid.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's `CKDOutput` and unconditionally adds the two group elements together: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant is supposed to compute:

- `big_y  = λᵢ · yᵢ · G`  (blinding term)
- `big_c  = λᵢ · (xᵢ · H(pk ‖ app_id) + yᵢ · app_pk)`  (key share)

as shown in `compute_signature_share`: [2](#0-1) 

The coordinator then sums all `big_y` and `big_c` values and returns the aggregate as the `CKDOutput`. There is **no proof-of-knowledge**, **no commitment-then-reveal**, and **no consistency check** that verifies:

1. `big_y` is of the form `λᵢ · yᵢ · G` for any `yᵢ`,
2. `big_c` uses the participant's actual private share `xᵢ` and the same `yᵢ` used in `big_y`.

This is the direct analog of the M-01 pattern: just as the audited ERC-20 code removed balance checks and did not verify transfer return values, the CKD coordinator removes the only layer that could detect a malformed contribution — it never checks what it receives before incorporating it into the aggregate.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept an incorrect cryptographic output.**

The final `CKDOutput` is `(Σ big_y, Σ big_c)`. The `unmask` step computes:

```
Σ big_c − app_sk · Σ big_y  =  msk · H(pk ‖ app_id)
```

If any single participant substitutes arbitrary points `(Y', C')` for their legitimate contribution, the aggregate shifts by `(Y' − Y_honest, C' − C_honest)`, producing a value that is not `msk · H(pk ‖ app_id)`. The coordinator returns this corrupted value as `Some(ckd_output)` with no error, and every honest caller of `unmask` silently derives the wrong secret.

---

### Likelihood Explanation

**Medium.** Any participant in the CKD protocol can trigger this. The participant role is reachable by any party that holds a valid key share and is included in the `participants` list. No privileged access beyond normal protocol participation is required. The attack requires only that the malicious party deviate from the honest computation in `compute_signature_share` and send crafted bytes over the private channel to the coordinator.

---

### Recommendation

Add a zero-knowledge proof (e.g., a Schnorr proof-of-knowledge) that each participant's `(big_y, big_c)` is correctly formed with respect to their committed public key share. Alternatively, use a commit-then-reveal scheme so that participants bind their contribution before seeing others', and the coordinator verifies each opening before aggregating. At minimum, document that the protocol assumes all participants are honest and that a single malicious participant can corrupt the output — if that is the intended trust model.

---

### Proof of Concept

1. Malicious participant `P_m` is included in the `participants` list with a valid key share.
2. Instead of calling `compute_signature_share` honestly, `P_m` sends `(G, G)` (the generator point) as `(norm_big_y, norm_big_c)` to the coordinator via `chan.send_private`.
3. The coordinator's loop at lines 50–55 adds `G` to both running sums without any check.
4. The resulting `CKDOutput` satisfies `Σ big_c − app_sk · Σ big_y ≠ msk · H(pk ‖ app_id)`.
5. The coordinator returns `Some(ckd_output)` — no error is raised, and every honest party that calls `unmask` on this output derives the wrong confidential key.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
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
