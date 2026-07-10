After exhaustively reviewing all production source files with `with_capacity` usages, none exhibit the exact C++ pattern (capacity-only allocation followed by index write). All Rust `Vec::with_capacity()` calls are correctly followed by `push()`.

However, the **structural analog** in this Rust codebase is: receiving a network-supplied `Vec<_>` and indexing into it with `[i]` up to a compile-time constant `N`, without first validating that the received vector has at least `N` elements. This is the same root cause class — assuming a collection has a certain number of accessible elements without verification — and causes a Rust index-out-of-bounds **panic** (denial of service) rather than C++ UB.

---

### Title
Unvalidated Network-Received Vector Length Before Index Access in Triple Generation Causes Panic-Based DoS - (File: `src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

### Summary
In `do_generation_many`, multiple network-received `Vec` values are indexed directly with `[i]` inside `for i in 0..N` loops, with no prior check that the received vector has at least `N` elements. A malicious participant can send a shorter-than-expected vector at any of these receive points, triggering a Rust index-out-of-bounds panic that aborts triple generation for all honest participants.

### Finding Description
`do_generation_many` is the core of the OT-based ECDSA Beaver triple generation protocol. It receives several `Vec`-typed messages from other participants and indexes into them with the compile-time constant `N`:

**Occurrence 1 — commitment phase (line 180–183):**
```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]); // panics if commitments.len() < N
}
``` [1](#0-0) 

**Occurrence 2 — polynomial commitments phase (lines 335–342):**
```rust
for i in 0..N {
    let their_big_e = &their.big_e_v[i];   // panics if big_e_v.len() < N
    let their_big_f = &their.big_f_v[i];
    let their_big_l = &their.big_l_v[i];
    let their_randomizer = &their.randomizer_v[i];
    let their_phi_proof0 = &their.phi_proof0_v[i];
    let their_phi_proof1 = &their.phi_proof1_v[i];
``` [2](#0-1) 

**Occurrence 3 — big_c aggregation phase (lines 470–475):**
```rust
for i in 0..N {
    let big_c_j = big_c_j_v[i].value();       // panics if big_c_j_v.len() < N
    let their_phi_proof = &their_phi_proofs[i];
``` [3](#0-2) 

**Occurrence 4 — hat_big_c aggregation phase (lines 589–591):**
```rust
for i in 0..N {
    let their_hat_big_c = their_hat_big_c_i_points[i].value(); // panics if len < N
    let their_phi_proof = &their_phi_proofs[i];
``` [4](#0-3) 

**Occurrence 5 — c_i accumulation phase (lines 629–631):**
```rust
for i in 0..N {
    let c_j_i = c_j_i_v[i].0;   // panics if c_j_i_v.len() < N
    c_i_v[i] += c_j_i;
``` [5](#0-4) 

None of these receive sites validate `received_vec.len() >= N` before the loop. The `PolynomialCommitmentsMessageMany` struct contains multiple `Vec` fields that are deserialized from the wire; serde will happily deserialize a zero-length or short vector. [6](#0-5) 

The entry point exposed to callers is `generate_triple_many` (and `generate_triple`, which calls `do_generation_many::<1>`): [7](#0-6) 

### Impact Explanation
Triple generation is the mandatory offline phase for OT-based ECDSA presigning and signing. A panic in `do_generation_many` propagates through the `ProtocolExecutor::poke` polling loop, aborting the protocol for the honest participant. Because the malicious participant can repeat this on every retry attempt, honest parties are permanently denied the ability to generate Beaver triples and thus cannot produce presignatures or signatures. This matches: **High — Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions.**

### Likelihood Explanation
Any participant in the triple generation session can send a malformed message. The attacker only needs to be a registered participant (no key material or cryptographic capability required). The attack is trivially repeatable on every protocol invocation, making it a reliable and persistent DoS. Likelihood is **High**.

### Recommendation
Before each `for i in 0..N` loop that indexes into a network-received `Vec`, add an explicit length check and return a `ProtocolError` on failure. For example, at the commitment receive site:

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
if commitments.len() < N {
    return Err(ProtocolError::AssertionFailed(
        format!("Expected {N} commitments, got {}", commitments.len())
    ));
}
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]);
}
```

Apply the same pattern to all five receive sites in `do_generation_many` and to any analogous sites in other `_many` functions.

### Proof of Concept
A malicious participant `M` in a triple generation session with honest parties `A`, `B`:

1. `M` participates normally until `wait0` (commitment broadcast round).
2. Instead of sending `Vec` of length `N`, `M` sends an empty `Vec<Commitment>` (serialized as `[]`).
3. When `A` or `B` receives this message and executes `commitments[0]`, Rust panics with an index-out-of-bounds error.
4. The panic propagates through `ProtocolExecutor::poke`, aborting the triple generation for `A` and `B`.
5. `M` repeats on every retry, permanently denying `A` and `B` the ability to generate triples and sign.

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L180-184)
```rust
        let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
        for i in 0..N {
            all_commitments_vec[i].put(from, commitments[i]);
        }
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L335-342)
```rust
            for i in 0..N {
                let all_commitments = &all_commitments_vec[i];
                let their_big_e = &their.big_e_v[i];
                let their_big_f = &their.big_f_v[i];
                let their_big_l = &their.big_l_v[i];
                let their_randomizer = &their.randomizer_v[i];
                let their_phi_proof0 = &their.phi_proof0_v[i];
                let their_phi_proof1 = &their.phi_proof1_v[i];
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L470-475)
```rust
            for i in 0..N {
                let big_e_j_zero = &big_e_j_zero_v[i];
                let big_f = &big_f_v[i];

                let big_c_j = big_c_j_v[i].value();
                let their_phi_proof = &their_phi_proofs[i];
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L589-591)
```rust
        for i in 0..N {
            let their_hat_big_c = their_hat_big_c_i_points[i].value();
            let their_phi_proof = &their_phi_proofs[i];
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L629-631)
```rust
        for i in 0..N {
            let c_j_i = c_j_i_v[i].0;
            c_i_v[i] += c_j_i;
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
