Based on my investigation, I have a clear picture of the code path. Let me summarize the findings.

**Key facts established:**

1. `PolynomialCommitmentsMessageMany` has six `Vec<_>` fields, all expected to have exactly `N` elements.
2. `recv_from_others` deserializes the message via `rmp_serde::decode::from_slice`. A `Vec` with N-1 elements deserializes successfully — `rmp_serde` reads the length from the msgpack payload and produces a shorter Vec without error.
3. After deserialization, the loop `for i in 0..N` directly indexes all six fields with `[i]` — no length check precedes this.
4. `ProtocolExecutor::poke()` polls the future with no `catch_unwind`. A panic propagates directly to the caller.

---

### Title
Unchecked Vec length in `PolynomialCommitmentsMessageMany` causes index-out-of-bounds panic in `do_generation_many`, permanently aborting triple generation — (`src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

### Summary
When `generate_triple_many::<N>` runs with `N > 1`, a malicious participant can send a round-2 `PolynomialCommitmentsMessageMany` message where any of the six `Vec` fields (`big_e_v`, `big_f_v`, `big_l_v`, `randomizer_v`, `phi_proof0_v`, `phi_proof1_v`) contains fewer than `N` elements. Deserialization succeeds, but the subsequent `for i in 0..N` loop panics on the first out-of-bounds index access. Because `ProtocolExecutor::poke()` has no `catch_unwind`, the panic propagates to the caller, permanently aborting triple generation for every honest party that receives the message.

### Finding Description

`PolynomialCommitmentsMessageMany` is defined with six `Vec` fields: [1](#0-0) 

After receiving and deserializing this message in round 2, `do_generation_many` iterates `for i in 0..N` and directly indexes all six fields: [2](#0-1) 

There is no guard that checks `their.randomizer_v.len() == N` (or any of the other five fields) before entering the loop. `rmp_serde` deserializes a `Vec<T>` by reading the element count from the msgpack stream; a Vec with N-1 elements deserializes without error: [3](#0-2) 

When `i` reaches `N-1` and the Vec has only `N-1` elements, Rust's `[]` operator panics. `ProtocolExecutor::poke()` polls the future directly with no `catch_unwind`: [4](#0-3) 

The panic unwinds through `poke()` to the integrator's message-dispatch loop, crashing or aborting the honest party's protocol instance.

### Impact Explanation

A single malicious participant broadcasts one malformed `PolynomialCommitmentsMessageMany` (any Vec field truncated by one element). Every honest party that processes the message panics and permanently loses its triple-generation session. Because `generate_triple_many` is the prerequisite for OT-based ECDSA presigning, this constitutes **permanent denial of signing** for all honest parties under valid protocol inputs.

### Likelihood Explanation

The attack requires only that the malicious participant be a registered member of the triple-generation session (a normal protocol precondition). No cryptographic break is needed. The malformed message is trivially constructable by serializing a `PolynomialCommitmentsMessageMany` with one Vec shortened by one element. The attack is repeatable across every session attempt.

### Recommendation

Add an explicit length check for all six Vec fields immediately after deserialization, before the indexing loop:

```rust
if their.big_e_v.len() != N
    || their.big_f_v.len() != N
    || their.big_l_v.len() != N
    || their.randomizer_v.len() != N
    || their.phi_proof0_v.len() != N
    || their.phi_proof1_v.len() != N
{
    return Err(ProtocolError::AssertionFailed(format!(
        "message from {from:?} has wrong vector lengths"
    )));
}
```

This converts the panic into a graceful `ProtocolError`, consistent with how other malformed-message cases are handled (e.g., the degree check at lines 343–351). [5](#0-4) 

### Proof of Concept

1. Run `generate_triple_many::<2>` with 3 participants.
2. Intercept the round-2 `PolynomialCommitmentsMessageMany` from the malicious participant.
3. Re-serialize it with `randomizer_v` truncated to length 1 (instead of 2).
4. Deliver the message to any honest party.
5. Assert that `poke()` panics (index out of bounds) rather than returning `Err(ProtocolError::AssertionFailed(...))`.

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L343-351)
```rust
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

**File:** src/protocol/internal.rs (L338-340)
```rust
        let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
            rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
        Ok((from, decoded?))
```

**File:** src/protocol/internal.rs (L505-508)
```rust
            if let std::task::Poll::Ready(result) = fut.poll_unpin(&mut cx) {
                self.result = Some(result);
                self.fut = None;
            }
```
