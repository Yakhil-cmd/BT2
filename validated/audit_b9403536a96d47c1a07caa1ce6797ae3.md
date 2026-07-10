### Title
Missing Length Validation on Received Vectors in `do_generation_many` Causes Index-Out-of-Bounds Panic — (`File: src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

---

### Summary

In `do_generation_many`, multiple vectors received from remote participants are indexed with `for i in 0..N` loops without first validating that the received vectors contain exactly `N` elements. A malicious participant can send a vector shorter than `N` to trigger an index-out-of-bounds panic, crashing the triple generation protocol for all honest participants and permanently denying them the ability to generate triples (and thus sign).

---

### Finding Description

`do_generation_many` is the core of the OT-based ECDSA triple generation protocol. It is parameterized by a compile-time constant `N` (the number of triples to generate). All locally-created vectors are correctly sized to `N`. However, vectors received from remote participants over the channel are never validated to have length `N` before being indexed.

**Instance 1 — Commitment vector (line 180–183):**

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]); // panics if commitments.len() < N
}
```

`commitments` is deserialized from a remote message. A malicious participant can send a `Vec<Commitment>` with 0 elements; `commitments[0]` panics immediately.

**Instance 2 — `PolynomialCommitmentsMessageMany` vectors (lines 335–342):**

```rust
for (from, their) in recv_from_others::<PolynomialCommitmentsMessageMany>(...).await? {
    for i in 0..N {
        let their_big_e   = &their.big_e_v[i];   // panics if their.big_e_v.len() < N
        let their_big_f   = &their.big_f_v[i];
        let their_big_l   = &their.big_l_v[i];
        let their_randomizer  = &their.randomizer_v[i];
        let their_phi_proof0  = &their.phi_proof0_v[i];
        let their_phi_proof1  = &their.phi_proof1_v[i];
```

`PolynomialCommitmentsMessageMany` is a struct with six independent `Vec` fields. None of them are validated to have length `N` before indexing. A malicious participant can send any one of these fields as an empty `Vec`.

The same pattern recurs at four additional receive sites in the same function:
- Line ~407: `a_j_i_v[i]` / `b_j_i_v[i]` (private share vectors)
- Line ~474: `big_c_j_v[i]` / `their_phi_proofs[i]` (C-point and dlogeq proof vectors)
- Line ~590: `their_hat_big_c_i_points[i]` / `their_phi_proofs[i]` (hat-C-point vectors)
- Line ~630: `c_j_i_v[i]` (L-polynomial share vectors)

---

### Impact Explanation

Triple generation (`generate_triple` / `generate_triple_many`) is a mandatory prerequisite for every signing operation in the OT-based ECDSA path. A malicious participant who sends a zero-length (or under-length) vector at any of the six receive sites causes an unrecoverable Rust index-out-of-bounds panic in every honest participant's protocol instance. Because the panic is not converted to a `ProtocolError`, it propagates out of the async task and cannot be handled gracefully by the caller. This permanently denies honest parties the ability to complete triple generation and therefore to sign, matching the **High: Permanent denial of signing for honest parties** impact category.

---

### Likelihood Explanation

Any single participant included in a `generate_triple_many` session can trigger this. The attack requires only sending a well-formed but short `Vec` (e.g., length 0) in place of the expected length-`N` vector. No cryptographic material, key leakage, or external compromise is needed. The attacker-controlled entry path is the standard message-passing channel used by every participant.

---

### Recommendation

Add an explicit length check immediately after deserializing each received vector, before the `for i in 0..N` loop. For example, at the commitment receive site:

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
if commitments.len() != N {
    return Err(ProtocolError::AssertionFailed(format!(
        "commitments from {from:?}: expected {N} elements, got {}",
        commitments.len()
    )));
}
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]);
}
```

Apply the same guard to all six receive sites in `do_generation_many`, and to each field of `PolynomialCommitmentsMessageMany` individually.

---

### Proof of Concept

1. Participant A runs `generate_triple_many::<2>` with honest participants B and C.
2. At `wait0`, instead of sending `Vec<Commitment>` of length 2, A sends `vec![]` (empty).
3. B and C receive the empty vector and enter `for i in 0..2 { ... commitments[i] ... }`.
4. On `i = 0`, `commitments[0]` panics: *"index out of bounds: the len is 0 but the index is 0"*.
5. The triple generation protocol crashes for B and C; no triples are produced; signing is impossible. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L400-412)
```rust
        for (_, (a_j_i_v, b_j_i_v)) in recv_from_others::<(
            Vec<SerializableScalar<C>>,
            Vec<SerializableScalar<C>>,
        )>(&chan, wait3, &participants, me)
        .await?
        {
            for i in 0..N {
                let a_j_i = &a_j_i_v[i];
                let b_j_i = &b_j_i_v[i];
                a_i_v[i] += &a_j_i.0;
                b_i_v[i] += &b_j_i.0;
            }
        }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L464-494)
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L626-633)
```rust
    for (_, c_j_i_v) in
        recv_from_others::<Vec<SerializableScalar<C>>>(&chan, wait6, &participants, me).await?
    {
        for i in 0..N {
            let c_j_i = c_j_i_v[i].0;
            c_i_v[i] += c_j_i;
        }
    }
```
