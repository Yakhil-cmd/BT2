The code is clear. Let me trace the exact path:

**Lines 151–157**: `(alpha_j, beta_j)` from every participant is summed into `alpha`/`beta` with no per-participant validation.

**Lines 162–168**: A single aggregate check `alpha*G == big_k + big_a` is performed. If any one participant sent a perturbed share, this check fails and `ProtocolError::AssertionFailed` is returned — with no indication of which participant caused it.

There is no commitment scheme, no ZK proof of correct computation, and no per-share attribution before aggregation. The error message at line 165 says only `"received incorrect shares of additive triple phase."` — it names no participant.

The SECURITY.md does not exclude active-abort DoS by a valid protocol participant. The RESEARCHER.md explicitly lists "Permanent lock/freeze states created through reachable user actions" as in-scope.

---

### Title
Malicious Participant Can Permanently Abort Presign Without Attribution — (`src/ecdsa/ot_based_ecdsa/presign.rs`)

### Summary
In Round 2 of `do_presign`, each participant's `(alpha_j, beta_j)` shares are aggregated without any per-participant binding or verification. The only check is an aggregate equality at lines 162–168. A single malicious participant can send a syntactically valid but arithmetically perturbed share, causing the aggregate check to fail for every honest party. Because the error provides no attribution, the malicious participant cannot be identified or excluded, allowing them to abort every presign session they participate in indefinitely.

### Finding Description
In `src/ecdsa/ot_based_ecdsa/presign.rs`, Round 2 proceeds as follows:

1. Each participant computes `alpha_i = k'_i + a'_i` and `beta_i = x'_i + b'_i` and broadcasts them. [1](#0-0) 

2. All received shares are summed into `alpha` and `beta` with no intermediate validation. [2](#0-1) 

3. A single aggregate check verifies `alpha*G == K + A` and `beta*G == X + B`. [3](#0-2) 

If a malicious participant sends `(alpha_j + delta, beta_j)` for any non-zero scalar `delta`, the aggregate `alpha` is shifted by `delta`, the check at line 162 fails, and every honest party receives `ProtocolError::AssertionFailed`. The error message carries no participant identity. There is no commitment to `(alpha_j, beta_j)` before the reveal, no ZK proof of correct computation, and no per-share verification loop — only the final aggregate check. [4](#0-3) 

### Impact Explanation
Every honest participant in the session aborts with an unattributed error. Since the malicious participant cannot be identified from the protocol output alone, honest parties cannot selectively exclude them and retry. The malicious participant can repeat this across every new presign session they are invited to, constituting permanent denial of signing for the honest set as long as the attacker remains a participant.

**Impact category**: High — Permanent denial of signing for honest parties under valid protocol inputs.

### Likelihood Explanation
The attacker only needs to be a valid protocol participant with legitimate triple and keygen shares — no privileged access, no cryptographic break required. The perturbation is a single scalar addition. The attack is trivially repeatable and undetectable from within the protocol.

### Recommendation
Bind each participant's `(alpha_j, beta_j)` contribution before aggregation so that a deviating participant can be identified:

- **Commitment-then-reveal**: Each participant commits to `(alpha_j*G, beta_j*G)` in a first sub-round, then reveals the scalars. After aggregation, each revealed scalar can be checked against its commitment, pinpointing the deviating party.
- **Per-share public-key check**: Since `alpha_j = k'_j + a'_j` and the public counterparts `K_j`, `A_j` are known (or derivable from the triple public data), verify `alpha_j * G == K'_j + A'_j` for each received share before summing.

Either approach converts the current unattributed aggregate abort into an identifiable abort, allowing honest parties to exclude the malicious participant and complete the protocol.

### Proof of Concept
```
Setup: n=3 participants, all with valid triple and keygen shares.
Participant P2 (malicious): sends (alpha_2 + Scalar::ONE, beta_2) at wait1.

Expected (honest protocol): alpha*G == big_k + big_a  ✓
Actual (with perturbation): (alpha + 1)*G == big_k + big_a + G  ✗

Result: All three participants return
  ProtocolError::AssertionFailed("received incorrect shares of additive triple phase.")
  with no indication that P2 is the source.

P2 repeats this in every subsequent presign session → permanent DoS.
``` [5](#0-4)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L136-143)
```rust
    let alpha_i: Scalar = k_prime_i + a_prime_i;
    // betai = xi' + bi'
    let beta_i: Scalar = x_prime_i + b_prime_i;

    // Send alphai and betai
    // Spec 2.2
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &(alpha_i, beta_i))?;
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L148-168)
```rust
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
