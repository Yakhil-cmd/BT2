### Title
Missing Length Validation Against Const Generic `N` in `do_generation_many` Causes Panic-Based DoS - (File: `src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

### Summary
The `do_generation_many<const N: usize>` function in the OT-based ECDSA triple generation protocol receives variable-length vectors from remote participants and indexes into them using `for i in 0..N` without first validating that the received vector contains at least `N` elements. A malicious participant can send a shorter-than-expected vector, triggering an index-out-of-bounds panic in every honest participant's process, permanently aborting triple generation.

### Finding Description

`do_generation_many<const N: usize>` is the core loop of the OT-based ECDSA Beaver triple generation protocol. It receives several network messages whose payload is a `Vec<T>` that is expected to have exactly `N` elements (one per triple being generated). In at least three distinct receive sites, the code iterates `for i in 0..N` and indexes the received vector with `received_vec[i]` — a Rust indexing operation that **panics** when `i >= received_vec.len()`.

**Site 1 — `wait0` commitment round** (lines 180–183):

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]); // panics if commitments.len() < N
}
``` [1](#0-0) 

**Site 2 — `wait2` polynomial commitment round** (lines 335–342):

```rust
for i in 0..N {
    let their_big_e = &their.big_e_v[i];   // panics if big_e_v.len() < N
    let their_big_f = &their.big_f_v[i];   // panics if big_f_v.len() < N
    let their_big_l = &their.big_l_v[i];   // panics if big_l_v.len() < N
    let their_randomizer = &their.randomizer_v[i]; // panics if randomizer_v.len() < N
    let their_phi_proof0 = &their.phi_proof0_v[i]; // panics if phi_proof0_v.len() < N
    let their_phi_proof1 = &their.phi_proof1_v[i]; // panics if phi_proof1_v.len() < N
``` [2](#0-1) 

**Site 3 — `wait5` hat-C / phi-proof round** (lines 589–591):

```rust
for i in 0..N {
    let their_hat_big_c = their_hat_big_c_i_points[i].value(); // panics if len < N
    let their_phi_proof = &their_phi_proofs[i];                // panics if len < N
``` [3](#0-2) 

**Site 4 — `wait6` private share round** (lines 626–632):

```rust
for (_, c_j_i_v) in
    recv_from_others::<Vec<SerializableScalar<C>>>(&chan, wait6, &participants, me).await?
{
    for i in 0..N {
        let c_j_i = c_j_i_v[i].0; // panics if c_j_i_v.len() < N
        c_i_v[i] += c_j_i;
    }
}
``` [4](#0-3) 

The deserialization of `Vec<T>` (or a struct containing `Vec<T>` fields) succeeds for **any** length — serde/rmp-serde imposes no minimum-length constraint. A malicious participant therefore sends a syntactically valid but length-0 (or length < N) vector. Deserialization succeeds, the `for i in 0..N` loop fires, and `received_vec[0]` panics immediately.

The `do_generation_many` function is called by both `do_generation` (single triple) and `generate_triple_many<N>` (batch triples). [5](#0-4) [6](#0-5) 

### Impact Explanation

A panic in an async Rust task propagates as an unrecoverable error in the protocol executor. Every honest participant running `generate_triple` or `generate_triple_many` will crash their protocol instance the moment they process the malicious message. Because triple generation is a prerequisite for OT-based ECDSA presigning and signing, the attacker permanently denies the ability to produce new presignatures or signatures for any session that includes the malicious participant.

This matches the allowed impact: **High — Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions.**

### Likelihood Explanation

Any participant in the triple generation session is a valid attacker. The protocol explicitly allows a configurable number of malicious participants (`max_malicious`). The attack requires only sending a single malformed message (a `Vec` with 0 elements) at any of the four vulnerable receive sites. No cryptographic material, leaked keys, or external assumptions are needed. The attack is trivially reproducible.

### Recommendation

Before indexing into any received vector with `for i in 0..N`, validate that the vector has exactly `N` elements and return a `ProtocolError` (not a panic) if it does not. For example, at each receive site:

```rust
if received_vec.len() != N {
    return Err(ProtocolError::AssertionFailed(format!(
        "expected {N} elements from {from:?}, got {}",
        received_vec.len()
    )));
}
```

Apply this check at all four sites: `wait0`, `wait2` (all six fields of `PolynomialCommitmentsMessageMany`), `wait5`, and `wait6`.

### Proof of Concept

1. Participant A joins a `generate_triple_many::<4>` session with honest participants B and C.
2. At the `wait0` round, instead of sending `Vec<Commitment>` of length 4, A sends a `Vec<Commitment>` of length 0 (serialized as an empty msgpack array).
3. When B and C receive A's message and execute `for i in 0..4 { all_commitments_vec[i].put(from, commitments[i]); }`, `commitments[0]` panics with an index-out-of-bounds error.
4. B and C's protocol instances crash. No triple is produced. Signing is permanently blocked for this session. [7](#0-6)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L70-85)
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
}
```

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L589-591)
```rust
        for i in 0..N {
            let their_hat_big_c = their_hat_big_c_i_points[i].value();
            let their_phi_proof = &their_phi_proofs[i];
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
