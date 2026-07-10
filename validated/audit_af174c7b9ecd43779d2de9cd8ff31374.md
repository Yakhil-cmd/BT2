### Title
Missing Triple Index in Fiat-Shamir Transcript Allows Cross-Triple Proof Reuse in `generate_triple_many` — (File: `src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

---

### Summary

The `create_transcript` function omits the batch count `N` from the Fiat-Shamir transcript, and the dlog proofs generated inside `do_generation_many` for each of the `N` triples all use the **same** transcript fork — with no triple index included. A malicious participant can therefore reuse the same polynomial and the same dlog proof across every triple in the batch without detection. The resulting triples are correlated, violating the independence assumption that the presigning protocol relies on for security.

---

### Finding Description

**Root cause — `create_transcript` omits `N`:** [1](#0-0) 

The transcript is seeded with only the group name, the participant list, and the threshold. The batch size `N` is never absorbed. Consequently, `generate_triple_many::<1>` and `generate_triple_many::<2>` (or any other `N`) produce an **identical** base transcript when called with the same participants and threshold.

**Root cause — loop body reuses the same transcript fork for every triple `i`:**

Inside `do_generation_many`, the loop over `0..N` generates a dlog proof for each triple's `a`-polynomial and `b`-polynomial: [2](#0-1) 

Both `transcript.fork(b"dlog0", &me.bytes())` and `transcript.fork(b"dlog1", &me.bytes())` are called with **no triple index `i`**. Every iteration of the loop forks from the same transcript state, producing an identical Fiat-Shamir context for all `N` triples.

The verifier mirrors this exactly: [3](#0-2) 

Because the verifier also uses `transcript.fork(b"dlog0", &from.bytes())` for every `i`, a proof that is valid for triple 0 is equally valid for triple 1, 2, …, N−1 **as long as the statement (the polynomial's constant-term commitment) is the same**.

**Concrete attack path:**

A malicious participant `P_m` proceeds as follows:

1. Chooses a single polynomial `e` (and `f`) and computes `big_e = e.commit_polynomial()`.
2. For each triple slot `i ∈ 0..N`, places the **same** `big_e` (and `big_f`) in `big_e_v[i]` / `big_f_v[i]`, but uses a **fresh randomizer** `r_i` for each Pedersen commitment `C_i = Commit(big_e, big_f, big_l; r_i)`. The Pedersen commitment check passes for every `i` because each `C_i` is a valid commitment to the same polynomial with a different blinder.
3. Generates **one** dlog proof `π` for `e.eval_at_zero()` using `transcript.fork(b"dlog0", &me.bytes())`.
4. Fills `phi_proof0_v[i] = π` for all `i`. The verifier accepts every copy because the statement and transcript fork are identical for all `i`.

Honest parties accept the full `PolynomialCommitmentsMessageMany` message and proceed. The malicious party's contribution to every triple's `a`-share is `e.eval_at_participant(me)` — the **same value** for all triples.

---

### Impact Explanation

The presigning protocol consumes **two** triples: [4](#0-3) 

- `triple0` supplies the nonce-related values: `k_i = triple0.a`, `e_i = triple0.c`.
- `triple1` supplies the blinding values: `a_i = triple1.a`, `b_i = triple1.b`, `c_i = triple1.c`.

When `generate_triple_many::<2>` is used to produce both triples in one batch, and the malicious party forces `triple0.a = triple1.a` (same polynomial), the malicious party's contribution satisfies `k_m = a_m`. The presigning then computes:

```
alpha = k + a  =  (k_m + Σ_honest k_j)  +  (a_m + Σ_honest a_j)
               =  2·k_m  +  Σ_honest (k_j + a_j)
```

The malicious party knows `k_m = a_m`, so they can compute `Σ_honest (k_j + a_j) = alpha − 2·k_m`. This leaks a linear combination of honest parties' secret nonce and blinding contributions. Combined with the presignature output `(R, k_i, sigma_i)` and the signing equation, this correlation breaks the independence assumption that the security proof for the OT-based ECDSA scheme requires, and opens a path toward recovering the secret key across multiple signing sessions.

**Mapped impact:** High — corruption of presign outputs so honest parties accept structurally invalid (correlated) triples, with a realistic path to secret key extraction.

---

### Likelihood Explanation

`generate_triple_many` is the **recommended** batch API (used in all benchmarks and the primary integration path). A single malicious participant among the triple-generation set — which can be as small as threshold `t` — can mount this attack without any external capability. No leaked keys, no cryptographic breaks, and no trusted-party compromise are required. [5](#0-4) 

---

### Recommendation

1. **Include the triple index `i` in every proof's transcript fork.** Replace:
   ```rust
   transcript.fork(b"dlog0", &me.bytes())
   ```
   with:
   ```rust
   transcript.fork(b"dlog0", &[me.bytes(), i.to_be_bytes()].concat())
   ```
   (or absorb `i` as a separate message before forking). Apply the same fix to `b"dlog1"` and to the corresponding verifier calls.

2. **Include `N` in `create_transcript`.** Absorb the batch count so that transcripts for different batch sizes are domain-separated:
   ```rust
   transcript.message(b"batch_size", &(N as u64).to_be_bytes());
   ```

3. **Apply the same audit to any other loop-iterated proof** in the codebase (e.g., the `dlogeq` proofs in later rounds of `do_generation_many`) to confirm they are similarly indexed.

---

### Proof of Concept

```
Participants: P_honest, P_malicious
N = 2 (generate_triple_many::<2>)
Threshold = 2

P_malicious:
  1. Sample polynomial e once; compute big_e = e.commit_polynomial()
  2. For i in {0, 1}:
       - Set big_e_v[i] = big_e  (same commitment)
       - Sample fresh r_i; compute C_i = Commit(big_e, big_f, big_l; r_i)
  3. Compute proof π = dlog::prove(transcript.fork("dlog0", me), e.eval_at_zero(), nonce)
  4. Set phi_proof0_v[0] = phi_proof0_v[1] = π

P_honest verifies:
  For i in {0, 1}:
    statement = big_e.eval_at_zero()   // same for both i
    fork      = transcript.fork("dlog0", P_malicious.bytes())  // same for both i
    dlog::verify(fork, statement, π)   // PASSES for both i

Result:
  triple0.a_malicious = e.eval_at_participant(P_malicious)
  triple1.a_malicious = e.eval_at_participant(P_malicious)  // identical
  → k_m = a_m in presigning → correlated nonce/blinding → security assumption violated
```

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L31-49)
```rust
fn create_transcript(
    participants: &ParticipantList,
    threshold: ReconstructionLowerBound,
) -> Result<Transcript, ProtocolError> {
    let mut transcript = Transcript::new(NEAR_TRIPLE_GENERATION_LABEL);

    transcript.message(b"group", NAME);

    let enc = rmp_serde::encode::to_vec(participants).map_err(|_| ProtocolError::ErrorEncoding)?;
    transcript.message(b"participants", &enc);
    // To allow interop between platforms where usize is different
    transcript.message(
        b"threshold",
        &u64::try_from(threshold.value())
            .expect("threshold should always fit in u64")
            .to_be_bytes(),
    );
    Ok(transcript)
}
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L235-267)
```rust
        for i in 0..N {
            let big_e_i = &big_e_i_v[i];
            let big_f_i = &big_f_i_v[i];
            let e = &e_v[i];
            let f = &f_v[i];
            // Spec 2.6
            let statement0 = dlog::Statement::<C> {
                public: &big_e_i.eval_at_zero()?.value(),
            };
            let witness0 = dlog::Witness::<C> {
                x: e.eval_at_zero()?,
            };
            let my_phi_proof0 = dlog::prove_with_nonce(
                &mut transcript.fork(b"dlog0", &me.bytes()),
                statement0,
                witness0,
                my_phi_proof0_nonces[i],
            )?;
            let statement1 = dlog::Statement::<C> {
                public: &big_f_i.eval_at_zero()?.value(),
            };
            let witness1 = dlog::Witness::<C> {
                x: f.eval_at_zero()?,
            };
            let my_phi_proof1 = dlog::prove_with_nonce(
                &mut transcript.fork(b"dlog1", &me.bytes()),
                statement1,
                witness1,
                my_phi_proof1_nonces[i],
            )?;
            my_phi_proof0v.push(my_phi_proof0);
            my_phi_proof1v.push(my_phi_proof1);
        }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L365-389)
```rust
                let statement0 = dlog::Statement::<C> {
                    public: &their_big_e.eval_at_zero()?.value(),
                };
                if !dlog::verify(
                    &mut transcript.fork(b"dlog0", &from.bytes()),
                    statement0,
                    their_phi_proof0,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlog proof from {from:?} failed to verify"
                    )));
                }

                let statement1 = dlog::Statement::<C> {
                    public: &their_big_f.eval_at_zero()?.value(),
                };
                if !dlog::verify(
                    &mut transcript.fork(b"dlog1", &from.bytes()),
                    statement1,
                    their_phi_proof1,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlog proof from {from:?} failed to verify"
                    )));
                }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L730-740)
```rust
pub fn generate_triple_many<const N: usize>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = TripleGenerationOutputMany>, InitializationError> {
    let (participants, threshold) = validate_triple_inputs(participants, threshold)?;
    let ctx = Comms::new();
    let fut = do_generation_many::<N>(ctx.clone(), participants, me, threshold, rng);
    Ok(make_protocol(ctx, fut))
}
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L72-89)
```rust
    let a_i = args.triple1.0.a;
    let b_i = args.triple1.0.b;
    let c_i = args.triple1.0.c;

    // Extracting triples public variables (A, B, _)
    // notice C is not used
    let big_a: ProjectivePoint = args.triple1.1.big_a.into();
    let big_b: ProjectivePoint = args.triple1.1.big_b.into();

    // Extracting triples private variables (ki, _, ei)
    // notice di is not used
    let k_i = args.triple0.0.a;
    let e_i = args.triple0.0.c;

    // Extracting triples public variables (K, D, E)
    let big_k: ProjectivePoint = args.triple0.1.big_a.into();
    let big_d = args.triple0.1.big_b;
    let big_e = args.triple0.1.big_c;
```
