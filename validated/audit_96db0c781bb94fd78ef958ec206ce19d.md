The code is clear. Let me confirm the exact flow and absence of per-participant validation.

The code is fully clear. Here is my determination:

---

### Title
Unauthenticated `beta_j` Aggregation Allows Single Malicious Participant to Permanently Abort Presign for All Honest Parties — (`src/ecdsa/ot_based_ecdsa/presign.rs`)

### Summary
In `do_presign`, Round 2 collects `(alpha_j, beta_j)` from every participant and blindly accumulates them with no per-participant validation. A single malicious participant sending a correct `alpha_j` but an arbitrary `beta_j` causes the post-aggregation check `beta*G == X + B` to fail for every honest party, permanently aborting the presign with no way to identify or exclude the cheater.

### Finding Description

In Round 2, each participant's `(alpha_j, beta_j)` is received and immediately summed: [1](#0-0) 

No per-participant commitment, zero-knowledge proof, or individual curve-point check is performed on the received scalars. The only integrity check is a single aggregate comparison performed after all values have been mixed together: [2](#0-1) 

Because the check operates on the aggregate `beta = SUM beta_j`, a single corrupted `beta_j` poisons the sum irreversibly. The error message and `ProtocolError::AssertionFailed` variant carry no attribution information, so honest parties cannot identify the cheater and retry without them.

Round 1 provides no protection: it only checks that `e_j != 0` and that `e*G == E`. [3](#0-2) 

The malicious participant passes Round 1 cleanly by sending a correct `e_j`, then injects the bad `beta_j` only at `wait1`.

The protocol header documents `threshold t = MaxMalicious + 1`, indicating the design intent is to tolerate malicious participants: [4](#0-3) 

Yet the presign implementation provides no mechanism to survive even one malicious `beta_j`.

### Impact Explanation
Every honest participant calls `return Err(ProtocolError::AssertionFailed(...))` at line 165. The presign is permanently aborted. The consumed Beaver triples cannot be reused (reuse breaks ECDSA security), so the attack also burns a triple pair per attempt, compounding the denial-of-service.

### Likelihood Explanation
Any participant in the presign session can execute this attack. No special privilege, leaked key, or cryptographic break is required — only the ability to send an arbitrary scalar as `beta_j`. The attack is repeatable at every presign invocation.

### Recommendation
Each participant must commit to their `(alpha_j, beta_j)` before revealing them, and the commitment must be verifiable against the public triple values. Concretely:

- Before sending `(alpha_j, beta_j)`, each participant broadcasts a Pedersen or curve-point commitment `alpha_j * G` and `beta_j * G`.
- After all commitments are received, participants open their scalars.
- Each honest party verifies `alpha_j * G` and `beta_j * G` individually before adding to the running sum, allowing identification and exclusion of the cheating participant.

Alternatively, require a zero-knowledge proof of correct formation (`beta_j = x_prime_j + b_prime_j`) tied to the public key share and triple commitment.

### Proof of Concept

```
1. Complete Round 1 honestly for all N participants.
2. For one malicious participant P_m, at wait1 send:
       alpha_j = k_prime_m + a_prime_m   // correct
       beta_j  = Scalar::ONE              // arbitrary wrong value
3. All honest participants aggregate:
       beta = (sum of honest beta_j) + Scalar::ONE
            ≠ x + b
4. Check at line 163: ProjectivePoint::GENERATOR * beta != big_x + big_b  → true
5. All honest participants return ProtocolError::AssertionFailed.
6. Presign is permanently aborted; triples are consumed.
``` [5](#0-4)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L114-131)
```rust
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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L136-168)
```rust
    let alpha_i: Scalar = k_prime_i + a_prime_i;
    // betai = xi' + bi'
    let beta_i: Scalar = x_prime_i + b_prime_i;

    // Send alphai and betai
    // Spec 2.2
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &(alpha_i, beta_i))?;

    // Receive and compute alpha = SUM_j alphaj
    // Receive and compute beta = SUM_j betaj
    // Spec 2.3
    let mut alpha = alpha_i;
    let mut beta = beta_i;

    for (_, (alpha_j, beta_j)) in
        recv_from_others::<(Scalar, Scalar)>(&chan, wait1, &participants, me).await?
    {
        // Spec 2.4
        alpha += alpha_j;
        beta += beta_j;
    }

    // alpha*G =?= K + A
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

**File:** docs/ecdsa/ot_based_ecdsa/signing.md (L6-6)
```markdown
### Note: the threshold $t = \mathsf{MaxMalicious} + 1$
```
