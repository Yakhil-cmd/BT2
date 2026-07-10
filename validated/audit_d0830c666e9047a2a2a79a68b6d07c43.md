### Title
Missing Participant-Set Binding in OT-Based ECDSA Presigning Enables Cross-Version Triple Reuse After Reshare — (File: `src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

The `presign` function in the OT-based ECDSA module explicitly omits the check that the presigning participant set matches the participant set that generated the Beaver triples. After a key reshare that changes the participant set (e.g., P0 → P1 where P1 ⊂ P0), old triples generated under P0 can be fed into a presigning session running under P1. Because the Lagrange linearization inside `do_presign` uses P1's coefficients to linearize triple shares that were secret-shared under P0's coefficients, the resulting presignature is mathematically incorrect. Honest parties accept this corrupted presignature, and every subsequent signing attempt fails.

---

### Finding Description

`TriplePub` records the participant set and threshold used during triple generation: [1](#0-0) 

The `presign` entry-point receives two `(TripleShare, TriplePub)` pairs and a separate `participants` slice for the presigning session. It validates only that the threshold values match, and explicitly documents that the participant-set check is skipped: [2](#0-1) 

Inside `do_presign`, every triple share and every key share is linearized with the Lagrange coefficient derived from the **presigning** participant set: [3](#0-2) 

For this linearization to be correct, the triple shares must have been secret-shared under the same participant set. The triple shares satisfy:

```
Σ_{i ∈ P0} λ_i(P0) · k_i = k
```

but `do_presign` computes:

```
Σ_{i ∈ P1} λ_i(P1) · k_i
```

When P1 ≠ P0 (e.g., after a reshare that removed participant C from {A,B,C} → {A,B}), `λ_i(P1) ≠ λ_i(P0)`, so the reconstructed nonce is wrong. The resulting `big_r`, `k`, and `sigma` fields of `PresignOutput` are all incorrect, and any signature produced from them fails verification.

The orchestration document explicitly models the multi-phase pipeline where different participant sets are used across triple generation, presigning, and signing: [4](#0-3) 

The `TriplePub.participants` field exists precisely to carry the triple-generation participant set forward, but `presign` never reads it for validation.

---

### Impact Explanation

A malicious coordinator, after a reshare from P0 to P1 (P1 ⊂ P0, same threshold), can instruct participants in P1 to reuse their pre-reshare triple shares. Because participants in P1 ∩ P0 legitimately hold those old shares, no individual participant can detect the mismatch locally. The presigning protocol completes without error, all honest parties store the corrupted `PresignOutput`, and every signing attempt using that presignature produces an invalid ECDSA signature. The coordinator can repeat this indefinitely, causing **permanent denial of signing** for honest parties under valid protocol inputs.

This matches the allowed High impact: *Corruption of presign outputs so honest parties accept unusable cryptographic outputs.*

---

### Likelihood Explanation

The attack requires:
1. A reshare that changes the participant set while keeping the threshold constant (so the only existing threshold check does not fire).
2. A malicious coordinator who instructs participants to supply pre-reshare triple shares to the new presigning session.

Both conditions are realistic. Reshares that remove participants are a documented use-case. The coordinator role is an explicitly modeled adversary in this library. Participants have no in-protocol way to distinguish old from new triple shares because `TriplePub.participants` is never validated against the presigning participant list.

---

### Recommendation

Inside `presign`, after constructing the `ParticipantList`, add a check that the presigning participant set is a subset of both `args.triple0.1.participants` and `args.triple1.1.participants`:

```rust
let triple0_participants = ParticipantList::new(&args.triple0.1.participants)
    .ok_or(InitializationError::DuplicateParticipants)?;
let triple1_participants = ParticipantList::new(&args.triple1.1.participants)
    .ok_or(InitializationError::DuplicateParticipants)?;

for p in participants.participants() {
    if !triple0_participants.contains(*p) || !triple1_participants.contains(*p) {
        return Err(InitializationError::BadParameters(
            "Presigning participant was not present during triple generation".to_string(),
        ));
    }
}
```

This ensures that the Lagrange basis used during presigning is consistent with the basis under which the triple shares were generated.

---

### Proof of Concept

1. Run DKG with P0 = {A, B, C}, threshold = 2. Each party obtains a `KeygenOutput`.
2. Generate two Beaver triples with P0 and threshold = 2. Each party in P0 obtains `(TripleShare, TriplePub)` where `TriplePub.participants = [A, B, C]`.
3. Run reshare from P0 to P1 = {A, B}, threshold = 2. A and B obtain new `KeygenOutput` values; C is removed.
4. A malicious coordinator instructs A and B to run `presign` with `participants = [A, B]` but supplies the **old** `TripleShare` values (from step 2) and the old `TriplePub` (threshold = 2, so the threshold check at line 43 passes).
5. `do_presign` computes `lambda_A({A,B})` and `lambda_B({A,B})`, which differ from `lambda_A({A,B,C})` and `lambda_B({A,B,C})`. The reconstructed nonce `k` and blinding value `sigma` are both wrong.
6. Both A and B output a `PresignOutput` with an incorrect `big_r`. No error is raised.
7. Any call to `sign` using this presignature produces an ECDSA signature that fails external verification, permanently blocking signing for A and B until fresh triples are generated. [5](#0-4) [1](#0-0)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/mod.rs (L56-65)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TriplePub {
    pub big_a: AffinePoint,
    pub big_b: AffinePoint,
    pub big_c: AffinePoint,
    /// The participants in generating this triple.
    pub participants: Vec<Participant>,
    /// The threshold which will be able to reconstruct it.
    pub threshold: ReconstructionLowerBound,
}
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L38-62)
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

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(ctx.shared_channel(), participants, me, args);
    Ok(make_protocol(ctx, fut))
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

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L31-57)
```markdown
Concretely, we have the following situation:

$$
\begin{matrix}
&\scriptsize{\text{Key-Gen}}
&&\scriptsize{\text{Triples}}
&&\scriptsize{\text{Presigning}}
&&\scriptsize{\text{Signing}}
\cr
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
$$
```
