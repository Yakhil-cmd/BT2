### Title
Missing Length Validation on Received `PolynomialCommitmentsMessageMany` Vectors Allows Malicious Participant to Abort Triple Generation — (`File: src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

### Summary
In `do_generation_many`, when a participant receives a `PolynomialCommitmentsMessageMany` message from another participant, the code directly indexes into six parallel `Vec` fields (`big_e_v`, `big_f_v`, `big_l_v`, `randomizer_v`, `phi_proof0_v`, `phi_proof1_v`) using `[i]` for `i in 0..N` without first verifying that every vector has exactly `N` elements. A malicious participant can send a crafted message where any of these vectors is shorter than `N`, triggering an out-of-bounds panic that aborts triple generation for all honest parties. Without triples, OT-based ECDSA signing cannot proceed.

### Finding Description

`PolynomialCommitmentsMessageMany` is a plain `#[derive(Serialize, Deserialize)]` struct with no custom deserialization that enforces equal lengths across its six `Vec` fields: [1](#0-0) 

After receiving this struct from a remote participant, `do_generation_many` immediately indexes into each field with `[i]` inside a `for i in 0..N` loop: [2](#0-1) 

There is no prior check that `their.big_e_v.len() == N`, `their.big_f_v.len() == N`, etc. If any vector has fewer than `N` elements, the `[i]` indexing panics at runtime.

The same pattern exists one round earlier, where the code receives a `Vec<Commitment>` and indexes it with `commitments[i]` for `i in 0..N`: [3](#0-2) 

Again, no length check is performed before indexing.

This is the direct analog of the external report: two (or more) related arrays that must have the same length `N` are used together without any length validation, causing a crash instead of a graceful error.

### Impact Explanation

A malicious participant in the OT-based ECDSA triple generation protocol can send a `PolynomialCommitmentsMessageMany` (or `Vec<Commitment>`) with any of the parallel vectors shorter than `N`. This causes an out-of-bounds panic in the receiving honest party's async task, aborting their instance of `do_generation_many`. Because the malicious participant can repeat this in every session, honest parties are permanently denied the ability to generate Beaver triples, which are a prerequisite for OT-based ECDSA presigning and signing.

**Allowed impact matched:** *High — Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions.*

### Likelihood Explanation

Any participant in the triple generation protocol can craft and send a malformed `PolynomialCommitmentsMessageMany` with mismatched vector lengths. The `#[derive(Deserialize)]` on the struct imposes no length constraints, so the crafted message deserializes successfully and the panic is reached deterministically on the first loop iteration where `i >= min_vector_len`. No cryptographic capability or key material is required; only the ability to participate in the protocol (i.e., be included in the `participants` list).

### Recommendation

Before the `for i in 0..N` loop, validate that every field of the received message has exactly `N` elements and return a `ProtocolError` (not a panic) if any mismatch is detected:

```rust
if their.big_e_v.len() != N
    || their.big_f_v.len() != N
    || their.big_l_v.len() != N
    || their.randomizer_v.len() != N
    || their.phi_proof0_v.len() != N
    || their.phi_proof1_v.len() != N
{
    return Err(ProtocolError::AssertionFailed(format!(
        "PolynomialCommitmentsMessageMany from {from:?} has wrong vector lengths"
    )));
}
```

Apply the same fix to the `Vec<Commitment>` received in round 1:

```rust
if commitments.len() != N {
    return Err(ProtocolError::AssertionFailed(...));
}
```

Alternatively, introduce a validated newtype for `PolynomialCommitmentsMessageMany` with a custom `Deserialize` implementation that enforces `len == N` at deserialization time, consistent with how `PolynomialCommitment` already enforces non-empty vecs in its own `Deserialize` impl. [4](#0-3) 

### Proof of Concept

1. Honest parties `P1`, `P2`, `P3` initiate `do_generation_many::<2>(...)` (N=2 triples).
2. Malicious `P_evil` participates normally through rounds 1–2 (sending valid commitments and confirmations).
3. In round 3, instead of sending a `PolynomialCommitmentsMessageMany` with all six vectors of length 2, `P_evil` sends one where `big_f_v` is an empty `Vec` (length 0).
4. When `P1` receives this message and executes `let their_big_f = &their.big_f_v[0]`, Rust panics with an index-out-of-bounds error.
5. `P1`'s async task aborts; triple generation fails. `P_evil` repeats this in every subsequent session, permanently blocking OT-based ECDSA signing for the honest parties.

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L331-351)
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
                if their_big_e.degree() != threshold.value() - 1
                    || their_big_f.degree() != threshold.value() - 1
                    // degree is threshold - 2 because the constant element identity is not serializable
                    || their_big_l.degree() != threshold.value() - 2
                {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "polynomial from {from:?} has the wrong length"
                    )));
                }
```

**File:** src/crypto/polynomials.rs (L381-391)
```rust
// Deserialization enforcing non-empty vecs and non all-identity PolynomialCommitments
impl<'de, C: Ciphersuite> Deserialize<'de> for PolynomialCommitment<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let coefficients = Vec::<CoefficientCommitment<C>>::deserialize(deserializer)?;
        Self::new(&coefficients)
            .map_err(|err| serde::de::Error::custom(format!("ProtocolError: {err}")))
    }
}
```
