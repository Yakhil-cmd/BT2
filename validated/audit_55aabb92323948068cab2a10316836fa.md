### Title
Missing Length Validation on Received Vectors in Triple Generation Causes Panic-Based Protocol Abort - (File: src/ecdsa/ot_based_ecdsa/triples/generation.rs)

### Summary
The triple generation protocol (`do_generation` / `do_generation_many`) receives dynamically-sized `Vec` messages from remote participants and immediately indexes them with `for i in 0..N` without first validating that the received vectors contain exactly `N` elements. A malicious participant can send a shorter-than-expected vector, triggering an index-out-of-bounds panic that aborts the protocol for all honest parties, permanently denying them the ability to generate Beaver triples and thus complete any OT-based ECDSA signing.

### Finding Description

In `src/ecdsa/ot_based_ecdsa/triples/generation.rs`, the inner async function `do_generation_many` (which backs both `generate_triple` and `generate_triple_many`) receives several `Vec`-typed messages from each remote participant and immediately indexes them with `for i in 0..N` where `N` is the compile-time const generic:

**Round 2 — `PolynomialCommitmentsMessageMany`** (lines ~331–396):
```rust
for (from, their) in
    recv_from_others::<PolynomialCommitmentsMessageMany>(&chan, wait2, &participants, me)
        .await?
{
    for i in 0..N {
        let their_big_e = &their.big_e_v[i];   // panics if len < N
        let their_big_f = &their.big_f_v[i];   // panics if len < N
        let their_big_l = &their.big_l_v[i];   // panics if len < N
        let their_randomizer = &their.randomizer_v[i];   // panics if len < N
        let their_phi_proof0 = &their.phi_proof0_v[i];  // panics if len < N
        let their_phi_proof1 = &their.phi_proof1_v[i];  // panics if len < N
        ...
    }
}
```

**Round 3 — share vectors** (lines ~400–412):
```rust
for (_, (a_j_i_v, b_j_i_v)) in recv_from_others::<(
    Vec<SerializableScalar<C>>,
    Vec<SerializableScalar<C>>,
)>(&chan, wait3, &participants, me).await?
{
    for i in 0..N {
        let a_j_i = &a_j_i_v[i];   // panics if len < N
        let b_j_i = &b_j_i_v[i];   // panics if len < N
        ...
    }
}
```

**Round 6 — `c` share vectors** (lines ~626–633):
```rust
for (_, c_j_i_v) in
    recv_from_others::<Vec<SerializableScalar<C>>>(&chan, wait6, &participants, me).await?
{
    for i in 0..N {
        let c_j_i = c_j_i_v[i].0;   // panics if len < N
        ...
    }
}
```

None of these sites validate `their.big_e_v.len() == N`, `a_j_i_v.len() == N`, or `c_j_i_v.len() == N` before indexing. The `PolynomialCommitmentsMessageMany` struct fields are plain `Vec`s whose length is entirely controlled by the serializing participant. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

A Rust index-out-of-bounds on a `Vec` is an unrecoverable panic. In an async context the panic unwinds the future, which the protocol executor surfaces as a fatal `ProtocolError`. Every honest participant running `generate_triple` / `generate_triple_many` with the malicious party will abort at the same round. Because Beaver triples are a prerequisite for every OT-based ECDSA presignature, a malicious participant who is part of the triple-generation group can permanently block all signing by any subset that includes them, simply by sending a zero-length (or otherwise short) vector in any of the three affected rounds.

**Matched allowed impact:** *High — Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions.*

### Likelihood Explanation

- The attacker only needs to be a legitimate participant in a triple-generation session (an unprivileged library caller).
- The attack requires sending a single malformed message (a `Vec` with fewer than `N` elements) in any of three protocol rounds.
- No cryptographic material, no key leakage, and no external assumptions are required.
- The malicious participant can repeat the attack across every retry attempt, making the denial persistent.

### Recommendation

Add an explicit length guard immediately after deserializing each received vector, before the `for i in 0..N` loop. For example:

```rust
if their.big_e_v.len() != N
    || their.big_f_v.len() != N
    || their.big_l_v.len() != N
    || their.randomizer_v.len() != N
    || their.phi_proof0_v.len() != N
    || their.phi_proof1_v.len() != N
{
    return Err(ProtocolError::AssertionFailed(format!(
        "participant {from:?} sent wrong number of polynomial commitments (expected {N})"
    )));
}
```

Apply the same pattern to the `(a_j_i_v, b_j_i_v)` and `c_j_i_v` receive sites. This converts a panic into a graceful, attributable protocol abort that identifies the malicious sender, consistent with how the codebase already handles other malformed messages (e.g., the degree check at lines 343–351). [4](#0-3) 

### Proof of Concept

1. Participant `M` (malicious) joins a `generate_triple_many::<2>` session with two honest participants `A` and `B`.
2. In round 2, instead of sending a `PolynomialCommitmentsMessageMany` whose `big_e_v` has 2 elements, `M` serializes a struct with `big_e_v: vec![]` (zero elements).
3. When `A` and `B` receive `M`'s message and execute `for i in 0..2 { let _ = &their.big_e_v[i]; }`, both panic with `index out of bounds: the len is 0 but the index is 0`.
4. Both honest participants' protocol futures abort; `generate_triple_many` returns an error for `A` and `B`.
5. `M` can repeat this in every retry, indefinitely preventing `A` and `B` from obtaining triples and thus from ever completing an OT-based ECDSA presignature or signature. [5](#0-4)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L331-396)
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

                if !all_commitments
                    .index(from)?
                    .check(
                        &(&their_big_e, &their_big_f, &their_big_l),
                        their_randomizer,
                    )
                    .map_err(|_| ProtocolError::PointSerialization)?
                {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "commitment from {from:?} did not match revealed F"
                    )));
                }
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

                big_e_j_zero_v[i].put(from, their_big_e.eval_at_zero()?);

                big_e_v[i] = big_e_v[i].add(their_big_e)?;
                big_f_v[i] = big_f_v[i].add(their_big_f)?;
                big_l_v[i] = big_l_v[i].add(their_big_l)?;
            }
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
