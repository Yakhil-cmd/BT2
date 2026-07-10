### Title
Unchecked Array Indexing on Network-Received Vectors in Triple Generation Protocol - (File: `src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

---

### Summary

In `do_generation_many`, multiple vectors received from remote participants are indexed directly with `[i]` where `i` iterates `0..N` (a const generic), without any prior check that the received vector has at least `N` elements. A malicious participant can send a shorter-than-expected vector, triggering an index-out-of-bounds panic that crashes the triple generation protocol for all honest parties.

---

### Finding Description

`do_generation_many<const N: usize>` is the core of the triple generation protocol. Throughout its execution it receives structured messages from other participants and immediately indexes into the deserialized vectors using `[i]` for `i in 0..N`. None of these indexing operations are guarded by a length check.

**Instance 1 – commitment vector (line 182):** [1](#0-0) 

`commitments` is the raw `Vec<_>` deserialized from a network message. If a malicious participant sends a vector with fewer than `N` elements, `commitments[i]` panics.

**Instance 2 – `PolynomialCommitmentsMessageMany` fields (lines 337–342):** [2](#0-1) 

`their.big_e_v[i]`, `their.big_f_v[i]`, `their.big_l_v[i]`, `their.randomizer_v[i]`, `their.phi_proof0_v[i]`, `their.phi_proof1_v[i]` are all indexed without checking that each inner `Vec` has length ≥ `N`.

**Instance 3 – private share vectors (lines 407–408):** [3](#0-2) 

`a_j_i_v` and `b_j_i_v` are received privately from each other participant and indexed without a length check.

**Instance 4 – `big_c_j_v` and proof vectors (lines 474–475):** [4](#0-3) 

**Instance 5 – hat commitment and proof vectors (lines 590–591):** [5](#0-4) 

**Instance 6 – `c_j_i_v` (line 630):** [6](#0-5) 

The public entry points `generate_triple` and `generate_triple_many` both funnel into `do_generation_many`: [7](#0-6) [8](#0-7) 

---

### Impact Explanation

Triples are a prerequisite for OT-based ECDSA signing. A panic in `do_generation_many` terminates the async task running the protocol for every honest participant in the session. Because Rust's `Vec` indexing with `[i]` panics (rather than returning an error) when `i >= len`, there is no way for the honest parties to catch and recover from this within the protocol. Any single malicious participant can abort every triple generation session indefinitely, permanently denying ECDSA signing capability to honest parties.

**Impact: High** – Permanent denial of signing for honest parties under valid protocol inputs.

---

### Likelihood Explanation

Any participant in the triple generation protocol can send a malformed message. The attacker only needs to be one of the `n` participants (no special role required). The attack requires sending a single message with a shorter-than-expected vector, which is trivially constructable. There is no authentication or length validation on the deserialized inner vectors before indexing.

**Likelihood: High**

---

### Recommendation

Before indexing into any network-received vector with `[i]` for `i in 0..N`, validate that the vector's length is at least `N` and return a `ProtocolError` (identifying the malicious sender) rather than panicking. For example:

```rust
if commitments.len() < N {
    return Err(ProtocolError::AssertionFailed(format!(
        "participant {from:?} sent a commitments vector of length {} but expected {N}",
        commitments.len()
    )));
}
```

Apply the same pattern to every other network-received vector that is subsequently indexed with `[i]` for `i in 0..N` throughout `do_generation_many`.

---

### Proof of Concept

1. Honest parties call `generate_triple_many::<2>` with `N = 2`.
2. The malicious participant serializes a `Vec<Commitment>` of length 1 (instead of 2) and sends it at `wait0`.
3. When an honest party receives this message and executes `commitments[1]`, Rust panics with `index out of bounds: the len is 1 but the index is 1`.
4. The async task for every honest participant crashes; triple generation is aborted and cannot complete.

### Citations

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L406-411)
```rust
            for i in 0..N {
                let a_j_i = &a_j_i_v[i];
                let b_j_i = &b_j_i_v[i];
                a_i_v[i] += &a_j_i.0;
                b_i_v[i] += &b_j_i.0;
            }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L470-476)
```rust
            for i in 0..N {
                let big_e_j_zero = &big_e_j_zero_v[i];
                let big_f = &big_f_v[i];

                let big_c_j = big_c_j_v[i].value();
                let their_phi_proof = &their_phi_proofs[i];

```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L589-592)
```rust
        for i in 0..N {
            let their_hat_big_c = their_hat_big_c_i_points[i].value();
            let their_phi_proof = &their_phi_proofs[i];

```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L629-632)
```rust
        for i in 0..N {
            let c_j_i = c_j_i_v[i].0;
            c_i_v[i] += c_j_i;
        }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L717-727)
```rust
pub fn generate_triple(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = TripleGenerationOutput>, InitializationError> {
    let (participants, threshold) = validate_triple_inputs(participants, threshold)?;
    let ctx = Comms::new();
    let fut = do_generation(ctx.clone(), participants, me, threshold, rng);
    Ok(make_protocol(ctx, fut))
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
