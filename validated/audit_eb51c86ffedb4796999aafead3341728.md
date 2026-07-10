### Title
Unauthenticated `beta_j` Shares Enable Unattributable Abort and Selective-Abort in OT-Based ECDSA Presign — (`src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

In `do_presign`, Round 2 collects `(alpha_j, beta_j)` shares from every participant and verifies only the **aggregate** `beta*G == X+B`. There is no per-participant commitment or proof binding each `beta_j` to the sender's public key share. A single malicious participant can send `beta_j = 0` (or any shifted value), causing the aggregate check to fail for **every** honest participant simultaneously. Because the loop discards the sender identity and the error is generic, no attribution is possible. The malicious participant can repeat this across sessions, permanently denying presign completion to honest parties, and can additionally perform a selective-abort attack after learning `R` in Round 1.

---

### Finding Description

**Round 2 share collection (lines 148–157):**

```rust
let mut alpha = alpha_i;
let mut beta = beta_i;

for (_, (alpha_j, beta_j)) in
    recv_from_others::<(Scalar, Scalar)>(&chan, wait1, &participants, me).await?
{
    alpha += alpha_j;
    beta += beta_j;
}
```

The sender identity is discarded (`_`). No per-participant check verifies `beta_j * G == X_j + B_j`.

**Aggregate-only check (lines 162–168):**

```rust
if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
    || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
{
    return Err(ProtocolError::AssertionFailed(
        "received incorrect shares of additive triple phase.".to_string(),
    ));
}
```

The error is a generic `AssertionFailed` string — no `MaliciousParticipant(participant)` variant is raised, so the caller cannot identify or exclude the offender.

**Correctness invariant:** The check passes iff `SUM_j beta_j = x + b` (where `x` is the secret key and `b` is the triple secret). If the malicious participant sends `beta_j = 0` instead of `lambda_j * x_j + lambda_j * b_j`, the aggregate is shifted by exactly `-malicious_beta_j`, the check fails, and **all** honest participants return `Err`.

**Selective-abort window:** In Round 1 (lines 107–131), every participant broadcasts `e_j` in plaintext. After Round 1 completes, the malicious participant knows the full scalar `e = SUM_j e_j` and the public point `D = big_d`. They can therefore compute `R = (1/e) * D` before sending anything in Round 2. They can choose to abort only sessions where `R` is unfavorable and complete the rest, biasing the distribution of accepted presignatures.

---

### Impact Explanation

- **Immediate DoS:** One malicious participant can abort every presign session for all honest parties with zero cost and no attribution. Honest parties cannot distinguish a network fault from a malicious abort.
- **Selective abort:** The malicious participant learns `R` at the end of Round 1 (before committing to Round 2 values). By aborting selectively, they can bias which `R` values appear in completed presignatures, which in ECDSA directly controls the nonce point used in signatures.

Impact category: **High — Permanent denial of signing for honest parties under valid protocol inputs.**

---

### Likelihood Explanation

Any participant with a valid triple share can execute this attack. It requires no privileged access, no leaked keys, and no cryptographic breaks. The attacker simply sends `(alpha_i, 0)` instead of `(alpha_i, beta_i)` in Round 2. The attack is repeatable across every presign session.

---

### Recommendation

Add per-participant commitments to `beta_j` before Round 2 begins (e.g., each participant broadcasts `beta_j * G` in Round 1 alongside `e_j`, then in Round 2 each received `beta_j` is verified against the committed point). This allows honest participants to identify and exclude the malicious sender rather than aborting the entire session. The same fix should be applied symmetrically to `alpha_j`.

---

### Proof of Concept

```
1. Run presign with participants [P1 (honest), P2 (honest), P3 (malicious)].
2. P3 completes Round 1 honestly (broadcasts correct e_3).
3. After Round 1, P3 computes R = (1/e) * D. If R is "unfavorable", proceed to step 4.
4. In Round 2, P3 sends (alpha_3, 0) instead of (alpha_3, beta_3).
5. P1 and P2 each compute beta = beta_1 + beta_2 + 0 ≠ x + b.
6. Both P1 and P2 hit the check at presign.rs:162–168 and return
   Err(AssertionFailed("received incorrect shares of additive triple phase.")).
7. Neither P1 nor P2 can identify P3 as the cause.
8. P3 retries with a fresh triple set until a favorable R is produced.
```

**Relevant lines:** [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L107-131)
```rust
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &e_i)?;

    // Receive ej and compute e = SUM_j ej
    // Spec 1.3
    let mut e = e_i;

    for (_, e_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
        if e_j.is_zero().into() {
            return Err(ProtocolError::AssertionFailed(
                "Received zero share of kd, indicating a triple wasn't available.".to_string(),
            ));
        }

        // Spec 1.4
        e += e_j;
    }

    // E =?= e*G
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L151-157)
```rust
    for (_, (alpha_j, beta_j)) in
        recv_from_others::<(Scalar, Scalar)>(&chan, wait1, &participants, me).await?
    {
        // Spec 2.4
        alpha += alpha_j;
        beta += beta_j;
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L162-168)
```rust
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }
```
