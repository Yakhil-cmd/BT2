### Title
Unchecked Index Access on Attacker-Controlled Vector Length in Triple Generation Causes Protocol Abort — (`File: src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

---

### Summary

In `do_generation_many`, multiple network-received `Vec` values are indexed at position `i` (for `i in 0..N`) without first verifying that the received vector contains at least `N` elements. A malicious participant can send a shorter-than-expected vector, triggering a Rust index-out-of-bounds panic that permanently aborts triple generation for all honest parties. Since triples are a prerequisite for OT-based ECDSA signing, this constitutes a permanent denial of signing.

---

### Finding Description

`do_generation_many<const N: usize>` is the core of the OT-based triple generation protocol. At multiple points it receives vectors from remote participants and immediately indexes them at `[i]` for `i in 0..N`, with no length validation:

**Instance 1 — Commitment vector (line 180–183):** [1](#0-0) 

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]); // panics if commitments.len() < N
}
```

**Instance 2 — `PolynomialCommitmentsMessageMany` fields (lines 335–342):** [2](#0-1) 

```rust
for i in 0..N {
    let their_big_e = &their.big_e_v[i];   // panics if len < N
    let their_big_f = &their.big_f_v[i];
    let their_big_l = &their.big_l_v[i];
    let their_randomizer = &their.randomizer_v[i];
    let their_phi_proof0 = &their.phi_proof0_v[i];
    let their_phi_proof1 = &their.phi_proof1_v[i];
```

**Instance 3 — Private share vectors (lines 406–411):** [3](#0-2) 

**Instance 4 — `big_c_j_v` and proof vectors (lines 470–475):** [4](#0-3) 

**Instance 5 — `hat_big_c_i_points` and proof vectors (lines 589–591):** [5](#0-4) 

**Instance 6 — `c_j_i_v` (lines 629–631):** [6](#0-5) 

The struct `PolynomialCommitmentsMessageMany` is fully attacker-controlled after deserialization — its inner `Vec` fields have no enforced length: [7](#0-6) 

The public entry point `generate_triple_many` passes `N` as a const generic but performs no validation that received messages contain exactly `N` elements: [8](#0-7) 

This is the direct analog of the Firedancer bank-tile bug: there, a C buffer pre-allocated for one transaction's maximum size is overflowed when multiple transactions are written. Here, a buffer (the const-generic `N`) is assumed to match the received vector length, but no enforcement exists, causing an out-of-bounds panic instead of a heap overflow.

---

### Impact Explanation

A Rust index-out-of-bounds panic unwinds and terminates the async task running the protocol. Because `do_generation_many` is the sole implementation of triple generation, and triples are a mandatory prerequisite for OT-based ECDSA presigning and signing: [9](#0-8) 

a single malicious participant can abort every triple generation session it participates in. Honest parties cannot produce triples, cannot presign, and cannot sign. This is **permanent denial of signing** for honest parties under valid protocol inputs.

This matches the allowed impact: **High: Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

Any participant in the triple generation protocol can trigger this. The attacker only needs to send a `Vec<Commitment>` (or any of the other affected message types) with fewer than `N` elements. This requires no cryptographic capability — only the ability to send a malformed message, which any protocol participant can do. The attack is deterministic and requires a single malformed message at the first round (`wait0`).

---

### Recommendation

Before indexing into any received vector at position `i` for `i in 0..N`, validate that the vector has exactly `N` elements and return a `ProtocolError` (not a panic) if not. For example, at each receive site:

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
if commitments.len() != N {
    return Err(ProtocolError::AssertionFailed(format!(
        "participant {from:?} sent {} commitments, expected {N}", commitments.len()
    )));
}
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]);
}
```

Apply the same length check to all six instances listed above, and to the fields of `PolynomialCommitmentsMessageMany` upon receipt.

---

### Proof of Concept

A malicious participant in a 3-party triple generation session with `N=2` sends the following at `wait0`:

```rust
// Malicious participant sends only 1 commitment instead of 2
let malicious_commitments: Vec<Commitment> = vec![some_valid_commitment]; // len=1, N=2
chan.send_many(wait0, &malicious_commitments)?;
```

When an honest participant receives this and executes:

```rust
for i in 0..2 {
    all_commitments_vec[i].put(from, commitments[i]); // panics at i=1: index 1 out of bounds for len 1
}
```

the thread panics with `index out of bounds: the len is 1 but the index is 1`, aborting the protocol for all honest participants. Triple generation cannot complete; signing is permanently unavailable for this session.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L70-84)
```rust
async fn do_generation(
    comms: Comms,
    participants: ParticipantList,
    me: Participant,
    threshold: ReconstructionLowerBound,
    rng: impl CryptoRngCore,
) -> Result<TripleGenerationOutput, ProtocolError> {
    let mut triple = do_generation_many::<1>(comms, participants, me, threshold, rng).await?;
    if triple.len() != 1 {
        return Err(ProtocolError::Other(
            "Triple generation did not output one element".to_string(),
        ));
    }
    let triple = triple.pop().expect("The triple exist");
    Ok(triple)
```

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L180-183)
```rust
        let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
        for i in 0..N {
            all_commitments_vec[i].put(from, commitments[i]);
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
