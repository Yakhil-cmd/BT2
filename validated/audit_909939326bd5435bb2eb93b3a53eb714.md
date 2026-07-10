### Title
Malicious Participant Can Trigger Index-Out-of-Bounds Panic in Triple Generation via Undersized Received Vectors - (File: src/ecdsa/ot_based_ecdsa/triples/generation.rs)

### Summary
In `do_generation_many`, multiple locations index into vectors received from remote participants using the compile-time constant `N` without first validating that the received vector has exactly `N` elements. A malicious participant can send a shorter-than-expected vector, causing a Rust index-out-of-bounds **panic** that crashes the triple generation protocol for all honest parties.

### Finding Description
The function `do_generation_many<const N: usize>` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs` receives several `Vec`-typed messages from remote participants and immediately indexes into them with `for i in 0..N { ... [i] }` without any length validation. There are four distinct vulnerable sites:

**Site 1 — Commitment vector (lines 180–183):**
```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]); // panics if commitments.len() < N
}
```
A malicious participant sends a `Vec` with fewer than `N` commitments. The code panics at `commitments[i]` when `i >= commitments.len()`.

**Site 2 — `PolynomialCommitmentsMessageMany` fields (lines 335–342):**
```rust
for i in 0..N {
    let their_big_e = &their.big_e_v[i];   // panics if big_e_v.len() < N
    let their_big_f = &their.big_f_v[i];   // panics if big_f_v.len() < N
    let their_big_l = &their.big_l_v[i];   // panics if big_l_v.len() < N
    let their_randomizer = &their.randomizer_v[i]; // panics if randomizer_v.len() < N
    let their_phi_proof0 = &their.phi_proof0_v[i]; // panics if phi_proof0_v.len() < N
    let their_phi_proof1 = &their.phi_proof1_v[i]; // panics if phi_proof1_v.len() < N
```
The `PolynomialCommitmentsMessageMany` struct contains six `Vec` fields, none of which are length-validated before indexing.

**Site 3 — `big_c_j_v` and `their_phi_proofs` (lines 470–475):**
```rust
for i in 0..N {
    let big_c_j = big_c_j_v[i].value();       // panics if big_c_j_v.len() < N
    let their_phi_proof = &their_phi_proofs[i]; // panics if their_phi_proofs.len() < N
```

**Site 4 — `their_hat_big_c_i_points` and `their_phi_proofs` (lines 589–591):**
```rust
for i in 0..N {
    let their_hat_big_c = their_hat_big_c_i_points[i].value(); // panics if len < N
    let their_phi_proof = &their_phi_proofs[i];                 // panics if len < N
```

The struct definition confirms no length enforcement at the type level: [1](#0-0) 

The vulnerable indexing at Site 1: [2](#0-1) 

The vulnerable indexing at Site 2: [3](#0-2) 

The vulnerable indexing at Site 3: [4](#0-3) 

The vulnerable indexing at Site 4: [5](#0-4) 

### Impact Explanation
In Rust, `vec[i]` where `i >= vec.len()` causes an unconditional **panic**, which aborts the async future and propagates as a protocol error to the honest party. Since Beaver triples are a prerequisite for OT-based ECDSA presigning and signing, a malicious participant who repeatedly crashes triple generation permanently denies honest parties the ability to produce signatures. This maps to:

**High: Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions.**

### Likelihood Explanation
**Medium.** Any participant enrolled in the triple generation protocol can trigger this by sending a single malformed message with a shorter-than-expected vector. No special privilege is required beyond being a protocol participant. The attack is trivially repeatable across every invocation of `generate_triple` or `generate_triple_many`.

### Recommendation
Before indexing into any remotely received `Vec` with `[i]` inside a `for i in 0..N` loop, validate that the vector has exactly `N` elements and return a `ProtocolError` on mismatch. For example, at each receive site:

```rust
if commitments.len() != N {
    return Err(ProtocolError::AssertionFailed(format!(
        "expected {N} commitments from {from:?}, got {}", commitments.len()
    )));
}
```

Apply the same guard to all six fields of `PolynomialCommitmentsMessageMany` and to the two-element tuples received at Sites 3 and 4.

### Proof of Concept
1. Honest parties call `generate_triple_many::<2>(...)` with `N = 2`.
2. The malicious participant serializes a `Vec` of length 1 (instead of 2) and sends it at `wait0`.
3. Honest parties receive the message and enter the loop `for i in 0..2`.
4. At `i = 1`, `commitments[1]` panics because `commitments.len() == 1`.
5. The panic propagates through the async runtime, aborting the triple generation protocol for all honest parties.
6. The malicious participant repeats this on every retry, permanently blocking triple generation and thus all OT-based ECDSA signing.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L97-106)
```rust
#[derive(Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
struct PolynomialCommitmentsMessageMany {
    big_e_v: Vec<PolynomialCommitment>,
    big_f_v: Vec<PolynomialCommitment>,
    big_l_v: Vec<PolynomialCommitment>,
    randomizer_v: Vec<Randomness>,
    phi_proof0_v: Vec<dlog::Proof<Secp256K1Sha256>>,
    phi_proof1_v: Vec<dlog::Proof<Secp256K1Sha256>>,
}
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L176-184)
```rust
    while all_commitments_vec
        .iter()
        .any(|all_commitments| !all_commitments.full())
    {
        let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
        for i in 0..N {
            all_commitments_vec[i].put(from, commitments[i]);
        }
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L331-342)
```rust
        for (from, their) in
            recv_from_others::<PolynomialCommitmentsMessageMany>(&chan, wait2, &participants, me)
                .await?
        {
            for i in 0..N {
                let all_commitments = &all_commitments_vec[i];
                let their_big_e = &their.big_e_v[i];
                let their_big_f = &their.big_f_v[i];
                let their_big_l = &their.big_l_v[i];
                let their_randomizer = &their.randomizer_v[i];
                let their_phi_proof0 = &their.phi_proof0_v[i];
                let their_phi_proof1 = &their.phi_proof1_v[i];
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L464-493)
```rust
        for (from, (big_c_j_v, their_phi_proofs)) in recv_from_others::<(
            Vec<CoefficientCommitment>,
            Vec<dlogeq::Proof<C>>,
        )>(&chan, wait4, &participants, me)
        .await?
        {
            for i in 0..N {
                let big_e_j_zero = &big_e_j_zero_v[i];
                let big_f = &big_f_v[i];

                let big_c_j = big_c_j_v[i].value();
                let their_phi_proof = &their_phi_proofs[i];

                let statement = dlogeq::Statement::<C> {
                    public0: &big_e_j_zero.index(from)?.value(),
                    generator1: &big_f.eval_at_zero()?.value(),
                    public1: &big_c_j,
                };

                if !dlogeq::verify(
                    &mut transcript.fork(b"dlogeq0", &from.bytes()),
                    statement,
                    their_phi_proof,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlogeq proof from {from:?} failed to verify"
                    )));
                }
                big_c_v[i] += big_c_j;
            }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L581-607)
```rust
    for (from, (their_hat_big_c_i_points, their_phi_proofs)) in recv_from_others::<(
        Vec<CoefficientCommitment>,
        Vec<dlog::Proof<C>>,
    )>(
        &chan, wait5, &participants, me
    )
    .await?
    {
        for i in 0..N {
            let their_hat_big_c = their_hat_big_c_i_points[i].value();
            let their_phi_proof = &their_phi_proofs[i];

            let statement = dlog::Statement::<C> {
                public: &their_hat_big_c,
            };
            if !dlog::verify(
                &mut transcript.fork(b"dlog2", &from.bytes()),
                statement,
                their_phi_proof,
            )? {
                return Err(ProtocolError::AssertionFailed(format!(
                    "dlog proof from {from:?} failed to verify"
                )));
            }
            hat_big_c_v[i] += &their_hat_big_c;
        }
    }
```
