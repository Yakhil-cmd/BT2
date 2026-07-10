### Title
No-Commitment Equivocation in Round-1 Share Distribution Enables Permanent Presign Abort — (`src/ecdsa/robust_ecdsa/presign.rs`)

### Summary

`do_presign` distributes private polynomial evaluations in Round 1 with no prior Feldman VSS commitment broadcast. A single malicious participant can send evaluations that are not consistent with any single polynomial to different honest parties. The resulting `k_i` values do not lie on a degree-t polynomial, so the exponent interpolation check at step 3.2 fails for every honest party, permanently aborting presign. Because no commitment was published, the cheater cannot be identified or excluded.

### Finding Description

**Round 1 — no commitment before private share distribution** [1](#0-0) 

Each participant generates five polynomials (`fk, fa, fb, fd, fe`) and immediately sends private evaluations to every other party via `chan.send_private`. No polynomial commitment (e.g., Feldman VSS: `[c_0·G, c_1·G, …, c_t·G]`) is broadcast before or alongside these private messages.

**Round 2 — received evaluations accepted without verification** [2](#0-1) 

Each party sums the received evaluations into its local `k_me` share with no check against any public commitment. A malicious party that sent `v_i ≠ fk_m(i)` to party `p_i` and `v_j ≠ fk_m(j)` to party `p_j` (where `v_i, v_j` are not evaluations of the same degree-t polynomial) causes the aggregate `k` values across honest parties to not lie on any degree-t polynomial.

**Round 3 — exponent interpolation check fails, aborting all honest parties** [3](#0-2) 

The check uses the first `t+1` broadcast `R_i = g^{k_i}` values to interpolate and verifies the remaining `t` values. Because `R_i` values are broadcast (`chan.send_many`), all parties see the same set. If the underlying `k_i` values are not on a degree-t polynomial, the interpolation will not reproduce the remaining `R_j` values, and every honest party returns `ProtocolError::AssertionFailed("Exponent interpolation check failed.")`.

**Contrast with DKG**

The DKG protocol in `src/dkg.rs` correctly uses Feldman VSS: it publishes a `VerifiableSecretSharingCommitment` before sending private shares and verifies each received share against it, preventing exactly this equivocation. [4](#0-3) 

The robust presign protocol has no equivalent protection.

**Enforcement of N = 2t+1 does not mitigate this**

The `presign` entry point enforces `participants.len() == 2*max_malicious+1` exactly to prevent split-view attacks. [5](#0-4) 

This means there is no slack in the participant set: if the attacker is one of the required `2t+1` participants, they can always trigger the abort. Since no commitment was published, honest parties have no cryptographic evidence to identify and exclude the cheater, making the denial permanent for any fixed participant set that includes the attacker.

### Impact Explanation

A single malicious participant (out of `2t+1`) can unconditionally abort every presign execution by sending inconsistent polynomial evaluations. Because the cheater cannot be identified (no commitments), honest parties cannot exclude them and retry successfully with the same participant set. This is a permanent denial of the presign phase, which blocks all downstream signing.

### Likelihood Explanation

The attack requires only that the attacker control one participant and be able to send different private messages to different recipients — the standard adversary model for this protocol. No cryptographic assumption needs to be broken. The attack is trivially executable in one round.

### Recommendation

Introduce a Feldman VSS commitment broadcast before Round 1 private share distribution, mirroring the DKG protocol:

1. Each party broadcasts polynomial commitments `[fk_i(0)·G, fk_i(1)·G, …]` (and similarly for `fa_i`) before or alongside the private evaluations.
2. Upon receiving a private evaluation `fk_ij`, each party verifies `fk_ij · G == eval_commitment(commitment_i, j)`.
3. If verification fails, the party aborts and can attribute the fault to the sender.

This eliminates equivocation: a malicious party can no longer send inconsistent evaluations without being detected and identified.

### Proof of Concept

```
Setup: N=5, t=2 (max_malicious=2), participants = [p1, p2, p3, p4, p5]
Attacker controls p1.

Round 1:
- p1 generates fk_1 (degree-2 polynomial) honestly.
- Instead of sending fk_1(j) to each p_j, p1 sends:
    fk_1(2) + delta  to p2   (delta ≠ 0)
    fk_1(3)          to p3
    fk_1(4)          to p4
    fk_1(5)          to p5

Round 2:
- p2 computes k_2 = fk_1(2)+delta + fk_2(2) + fk_3(2) + fk_4(2) + fk_5(2)
- p3 computes k_3 = fk_1(3)       + fk_2(3) + fk_3(3) + fk_4(3) + fk_5(3)
- (similarly for p4, p5)

The aggregate k values are:
  k_i = (sum of honest fk_j(i)) + fk_1(i) for i ∈ {3,4,5}
  k_2 = (sum of honest fk_j(2)) + fk_1(2) + delta

These do NOT lie on a degree-2 polynomial (the delta shifts k_2 off the curve).

Round 3:
- All parties broadcast R_i = g^{k_i}.
- Exponent interpolation using R_1,...,R_3 predicts R_4 and R_5.
- The prediction fails because k values are not on a degree-2 polynomial.
- All honest parties return Err(AssertionFailed("Exponent interpolation check failed.")).
- Presign is permanently aborted.
```

### Citations

**File:** src/ecdsa/robust_ecdsa/presign.rs (L74-79)
```rust
    // To prevent split-view attacks documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during presigning must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L114-127)
```rust
    // send polynomial evaluations to participants
    let wait_round_1 = chan.next_waitpoint();

    // Step 1.3
    for p in participants.others(me) {
        // Securely send to each other participant a secret share
        let package = polynomials
            .iter()
            .map(|poly| poly.eval_at_participant(p))
            .collect::<Result<Vec<_>, _>>()?;

        // send the evaluation privately to participant p
        chan.send_private(wait_round_1, p, &package)?;
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L133-139)
```rust
    // Step 2.1
    // Receive evaluations from all participants
    for (_, package) in recv_from_others(&chan, wait_round_1, &participants, me).await? {
        // Step 2.2
        // calculate the respective sum of the different shares received from each participant
        shares.add_shares(&package);
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L193-213)
```rust
    // check that the exponent interpolations match what has been received
    for (identifier, verifying_share) in identifiers
        .iter()
        .skip(threshold + 1)
        .zip(verifying_shares.iter().skip(threshold + 1))
    {
        // Step 3.2
        // exponent interpolation for (R0, .., Rt; i)
        let big_r_i = PolynomialCommitment::eval_exponent_interpolation(
            threshold_plus1_identifiers,
            threshold_plus1_verifying_shares,
            Some(identifier),
        )?;

        // check the interpolated R values match the received ones
        if big_r_i != *verifying_share {
            return Err(ProtocolError::AssertionFailed(
                "Exponent interpolation check failed.".to_string(),
            ));
        }
    }
```

**File:** src/dkg.rs (L379-405)
```rust
    // Compute the multiplication of every coefficient of p with the generator G
    // Step 2.4
    let coefficient_commitment = generate_coefficient_commitment::<C>(&secret_coefficients)?;

    // Generates a proof of knowledge if me is not holding the zero secret.
    let proof_domain_separator = domain_separator.clone();
    // Send none if me is a new participant
    let generate_proof: bool = old_participants.as_ref().is_none_or(|old| old.contains(me));
    // Step 2.5 2.6 2.7
    let proof_of_knowledge = if generate_proof {
        Some(proof_of_knowledge(
            &session_id,
            &mut domain_separator,
            me,
            &secret_coefficients,
            &coefficient_commitment,
            rng,
        )?)
    } else {
        // increment domain separator to match the old participants
        domain_separator.increment();
        None
    };

    // Create the public polynomial = secret coefficients times G
    let commitment =
        VerifiableSecretSharingCommitment::new(coefficient_commitment.get_coefficients());
```
