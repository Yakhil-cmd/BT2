### Title
Unchecked Index Access on Remotely-Supplied `Vec` Causes Panic in OT-Based Triple Generation — (File: `src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

### Summary
In `do_generation_many`, a `Vec` of commitments is received from a remote participant and immediately indexed with `commitments[i]` for `i in 0..N` without first verifying that the received vector has at least `N` elements. A malicious participant can send a shorter vector, causing an index-out-of-bounds panic that permanently aborts triple generation for all honest parties, blocking OT-based ECDSA presigning and signing.

### Finding Description
`do_generation_many` is the core of the OT-based Beaver triple generation protocol. In Round 1 (Spec 1.6), each participant broadcasts a `Vec<Commitment>` of exactly `N` elements. The receiving loop is:

```rust
// src/ecdsa/ot_based_ecdsa/triples/generation.rs  ~L176-183
while all_commitments_vec
    .iter()
    .any(|all_commitments| !all_commitments.full())
{
    let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
    for i in 0..N {
        all_commitments_vec[i].put(from, commitments[i]); // <-- panics if commitments.len() < N
    }
}
```

`commitments` is a `Vec<_>` deserialized from the network. Its length is entirely controlled by the sender. There is no guard such as `if commitments.len() != N { return Err(...); }` before the loop. When `i >= commitments.len()`, Rust's slice indexing panics with an index-out-of-range error.

The same unchecked pattern recurs later in the same function when processing `PolynomialCommitmentsMessageMany` fields (`their.big_e_v[i]`, `their.big_f_v[i]`, `their.big_l_v[i]`, `their.randomizer_v[i]`, `their.phi_proof0_v[i]`, `their.phi_proof1_v[i]`) and when accumulating `c_j_i_v[i]` shares, all inside `for i in 0..N` loops with no length pre-check. [1](#0-0) 

### Impact Explanation
Triple generation is the mandatory offline phase for OT-based ECDSA. A panic inside `do_generation_many` unwinds the async task for every honest participant running that session. Because the protocol never completes, no `TripleShare` outputs are produced. Without triples, `presign` cannot be called, and therefore signing is permanently unavailable for the affected session. Any single participant in the triple-generation session can trigger this.

This maps to: **High — Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions.**

### Likelihood Explanation
The attacker only needs to be one of the `N` participants invited to a triple-generation session. Sending a `Vec` with zero elements (or any length `< N`) is trivially achievable by crafting a custom serialized message. No cryptographic material or privileged access is required. The trigger is deterministic and reproducible.

### Recommendation
Before the indexing loop, validate that the received vector has exactly `N` elements and return a `ProtocolError` if not:

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
if commitments.len() != N {
    return Err(ProtocolError::AssertionFailed(
        format!("expected {N} commitments from {from:?}, got {}", commitments.len())
    ));
}
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]);
}
```

Apply the same length guard to every other `for i in 0..N` loop that indexes into a remotely-supplied `Vec` (`big_e_v`, `big_f_v`, `big_l_v`, `randomizer_v`, `phi_proof0_v`, `phi_proof1_v`, `c_j_i_v`).

### Proof of Concept
1. Participant A joins a triple-generation session with honest participants B and C, with `N = 4`.
2. In Round 1, instead of sending `Vec<Commitment>` of length 4, A sends a `Vec<Commitment>` of length 1.
3. When B (or C) receives A's message and executes `commitments[1]`, Rust panics with `index out of bounds: the len is 1 but the index is 1`.
4. The panic propagates out of `do_generation_many`, aborting the entire triple-generation session for B and C.
5. B and C can never obtain triples, and therefore can never call `presign` or produce ECDSA signatures. [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L109-116)
```rust
async fn do_generation_many<const N: usize>(
    comms: Comms,
    participants: ParticipantList,
    me: Participant,
    threshold: ReconstructionLowerBound,
    mut rng: impl CryptoRngCore,
) -> Result<TripleGenerationOutputMany, ProtocolError> {
    assert!(N > 0);
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L164-184)
```rust
    // Spec 1.6
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &my_commitments)?;

    // Spec 2.1
    let mut all_commitments_vec: Vec<ParticipantMap<Commitment>> = vec![];
    for comi in my_commitments.iter().take(N) {
        let mut m = ParticipantMap::new(&participants);
        m.put(me, *comi);
        all_commitments_vec.push(m);
    }

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
