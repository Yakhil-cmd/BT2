### Title
Missing Vec Length Validation Before Indexing in Triple Generation Round 1 Causes Panic — (`src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

---

### Summary

In `do_generation_many`, after receiving a `Vec<Commitment>` from a remote participant at `wait0`, the code directly indexes into the received vector with `commitments[i]` without first verifying that the vector has exactly `N` elements. A malicious participant can send an empty (or undersized) `Vec<Commitment>`, which deserializes successfully, and then cause an index-out-of-bounds **panic** in every honest party's triple generation task.

---

### Finding Description

In `src/ecdsa/ot_based_ecdsa/triples/generation.rs`, the round-1 receive loop is:

```rust
// lines 176–184
while all_commitments_vec
    .iter()
    .any(|all_commitments| !all_commitments.full())
{
    let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
    for i in 0..N {
        all_commitments_vec[i].put(from, commitments[i]); // ← panics if commitments.len() < N
    }
}
``` [1](#0-0) 

The `chan.recv` call deserializes the incoming bytes using `rmp_serde::decode::from_slice` into `Vec<Commitment>`:

```rust
// internal.rs lines 338–340
let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
    rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
Ok((from, decoded?))
``` [2](#0-1) 

An empty MessagePack array (`[]`) is a perfectly valid encoding of `Vec<Commitment>` with zero elements. Deserialization succeeds and returns `vec![]`. The subsequent `commitments[0]` (when `N=1`, the only production call path via `do_generation`) then panics unconditionally with an index-out-of-bounds error.

The production entry point always uses `N=1`:

```rust
// generation.rs line 77
let mut triple = do_generation_many::<1>(comms, participants, me, threshold, rng).await?;
``` [3](#0-2) 

There is **no length guard** anywhere between `chan.recv` and `commitments[i]`. The same pattern repeats for oversized vectors in later rounds (e.g., `their.big_e_v[i]`, `their.big_f_v[i]`, etc. at lines 337–342), but the round-1 path is the earliest and most accessible trigger. [4](#0-3) 

---

### Impact Explanation

Triple generation is a prerequisite for ECDSA presigning and signing. A panic in `do_generation_many` aborts the honest party's protocol task. Because the cooperative executor in `make_protocol` polls the async future directly, an unhandled panic propagates to the `poke()` caller and crashes the protocol instance. A single malicious participant can abort every triple generation session indefinitely by repeating this attack, permanently denying signing capability to all honest parties.

**Impact: High — Permanent denial of signing for honest parties.**

---

### Likelihood Explanation

Any participant in the triple generation protocol can trivially craft and send a zero-length (or wrong-length) `Vec<Commitment>` at round 1. No cryptographic material, no special privilege, and no prior state is required. The attack is deterministic and repeatable.

---

### Recommendation

Add an explicit length check immediately after receiving the commitment vector, before any indexing:

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
if commitments.len() != N {
    return Err(ProtocolError::AssertionFailed(format!(
        "participant {from:?} sent {} commitments, expected {N}",
        commitments.len()
    )));
}
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]);
}
```

Apply the same guard to every subsequent round that indexes into participant-supplied vectors (`PolynomialCommitmentsMessageMany` fields, `big_c_j_v`, `hat_big_c_i_points`, etc.).

---

### Proof of Concept

1. Set up a triple generation session with two participants (honest `P1`, malicious `P2`), `N=1`.
2. At `wait0`, instead of sending `vec![my_commitment]`, `P2` sends `vec![]` (an empty array serialized with `rmp_serde`).
3. `P1`'s `chan.recv(wait0)` successfully deserializes the empty vec.
4. `P1` executes `commitments[0]` → **panic: index out of bounds: the len is 0 but the index is 0**.
5. `P1`'s triple generation task aborts; `P1` can never complete presigning or signing.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L77-77)
```rust
    let mut triple = do_generation_many::<1>(comms, participants, me, threshold, rng).await?;
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

**File:** src/protocol/internal.rs (L338-341)
```rust
        let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
            rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
        Ok((from, decoded?))
    }
```
