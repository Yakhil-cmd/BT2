### Title
Missing Cross-Phase Participant-Set Validation Between Triple Generation and Presign Causes Permanent Denial of Signing - (File: src/ecdsa/ot_based_ecdsa/presign.rs)

### Summary
The OT-based ECDSA `presign()` function explicitly omits the check that the presign participant set is a subset of the triple generation participant set stored in `TriplePub.participants`. A malicious coordinator can announce a presign participant set that differs from the triple generation participant set, causing the Lagrange linearization to be computed with wrong coefficients. The resulting `alpha*G == K + A` assertion fails, permanently aborting the signing pipeline for all honest parties.

### Finding Description
The OT-based ECDSA signing pipeline requires three sequentially dependent phases: triple generation → presign → sign. The orchestration specification mandates `P ⊇ P0 ⊇ P1 ⊇ P2`, meaning each subsequent participant set must be a subset of the previous one. [1](#0-0) 

The `presign()` function explicitly acknowledges this omission:

```rust
// NOTE: We omit the check that the new participant set was present for
// the triple generation, because presumably they need to have been present
// in order to have shares.
```

The only cross-phase validation performed is a threshold equality check: [2](#0-1) 

The `TriplePub` struct stores the participant set used during triple generation: [3](#0-2) 

But `presign()` never reads `triple0.1.participants` or `triple1.1.participants` to validate them against the presign participant set. The Lagrange linearization inside `do_presign` uses the presign participant set exclusively: [4](#0-3) 

When the presign participant set differs from the triple generation participant set, `lambda_me` is computed for the wrong set. The linearized shares `k'_i`, `e_i`, `a'_i`, `b'_i`, `x'_i` are all scaled by wrong Lagrange coefficients. The aggregated `alpha` and `beta` values will not satisfy the public triple commitments `K` and `A`, causing the mandatory assertion to fail: [5](#0-4) 

### Impact Explanation
A malicious coordinator announces a presign participant set `P1` that differs from the triple generation participant set `P0` (e.g., by adding or substituting one participant). Each honest participant independently constructs `PresignArguments` using their own triple shares (generated for `P0`) but computes Lagrange coefficients for `P1`. The `alpha*G == K + A` check fails for every honest participant, permanently aborting the presign protocol. Since the triple shares are consumed (one-time use), the signing pipeline is permanently blocked for that batch of triples. This matches the allowed High impact: **Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions**. [6](#0-5) 

### Likelihood Explanation
The coordinator is a designated participant who announces the participant set for each protocol phase. A malicious coordinator can trivially announce `P1 ≠ P0` for the presign phase after triple generation completes with `P0`. Honest participants have no mechanism to detect this mismatch before executing `presign()`, because the library provides no API-level enforcement of the `P1 ⊆ P0` constraint. The `TriplePub.participants` field exists precisely to enable this check but is never consulted. [7](#0-6) 

### Recommendation
In `presign()`, after constructing the `ParticipantList` from the presign participants, validate that the presign participant set is a subset of both `args.triple0.1.participants` and `args.triple1.1.participants`. Return `InitializationError::BadParameters` if the constraint is violated. This mirrors the existing threshold cross-check and uses the already-stored `TriplePub.participants` field that is currently unused in validation.

### Proof of Concept
1. Run triple generation with participants `{A, B, C, D}`, threshold 2 → produces `TriplePub { participants: {A,B,C,D}, threshold: 2, ... }` and per-party `TripleShare`.
2. Malicious coordinator announces presign participant set `{A, B, C}` (threshold 2).
3. Each of A, B, C calls `presign(&[A,B,C], me, PresignArguments { triple0: (share_P0, pub_P0), triple1: (share_P0, pub_P0), threshold: 2, ... })`.
4. `presign()` passes the threshold check (`2 == 2`), skips the participant-set check.
5. Inside `do_presign`, `lambda_me = participants.lagrange::<Secp256>(me)` is computed for `{A,B,C}` instead of `{A,B,C,D}`.
6. `alpha = sum(k'_i + a'_i)` with wrong Lagrange coefficients; `alpha*G ≠ K + A` (where `K`, `A` are commitments from the `{A,B,C,D}` triple).
7. `ProtocolError::AssertionFailed("received incorrect shares of kd")` is returned for every honest participant.
8. The presign batch is permanently aborted; the consumed triple shares cannot be reused. [8](#0-7)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L38-47)
```rust
    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

    // Also check that we have enough participants to reconstruct shares.
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L49-57)
```rust
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L92-103)
```rust
    // Spec 1.1
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;

    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L125-131)
```rust
    // E =?= e*G
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L159-162)
```rust
    // alpha*G =?= K + A
    // beta*G =?= X + B
    // Spec 2.5
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L661-668)
```rust
            TriplePub {
                big_a,
                big_b,
                big_c,
                participants: participants.clone().into(),
                threshold,
            },
        ));
```

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L40-56)
```markdown
&\mathcal{P} &\supseteq &\mathcal{P}_0 &\supseteq &\mathcal{P}_1 &\supseteq &\mathcal{P}_2\cr
&N &\geq &N_0 &\geq &N_1 & \geq &N_2\cr
&t &&t_0 &&t_1 &&t_2\cr
\end{matrix}
$$

Each phase has a different set of parties, with each subsequent phase
having a subset of the parties present in the previous one.
The size of each party set, $N_i$, can also vary.
The thresholds can also change, subject to the following conditions:

$$
\begin{aligned}
&N_0 \geq t\cr
&N_1 \geq t_0 \geq t\cr
&N_2 \geq t_1 \geq t
\end{aligned}
```
