### Title
Missing Vec Length Validation After Deserialization Causes Panic in Triple Generation Protocol - (File: src/ecdsa/ot_based_ecdsa/triples/generation.rs)

### Summary

In `do_generation_many`, multiple protocol rounds deserialize `Vec`-typed fields from peer messages and immediately index into them with `[i]` for `i in 0..N` without first validating that the received vectors have the expected length `N`. A malicious participant can send a message with an empty or short vector, causing an index-out-of-bounds panic in every honest party's process, permanently aborting triple generation and thus OT-based ECDSA signing for the session.

### Finding Description

`do_generation_many` is the core of OT-based triple generation. It receives several messages whose fields are `Vec<T>` and are expected to have exactly `N` elements (where `N` is the compile-time const generic for batch size). After deserialization via `rmp_serde`, the code directly indexes these vectors without any length guard:

**Round 1 (Spec 2.1) — commitment collection, line 180–183:**
```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]); // panics if commitments.len() < N
}
```

**Round 3 (Spec 3.3) — `PolynomialCommitmentsMessageMany`, lines 331–342:**
```rust
for (from, their) in
    recv_from_others::<PolynomialCommitmentsMessageMany>(&chan, wait2, &participants, me).await?
{
    for i in 0..N {
        let their_big_e = &their.big_e_v[i];     // panics if len < N
        let their_big_f = &their.big_f_v[i];     // panics if len < N
        let their_big_l = &their.big_l_v[i];     // panics if len < N
        let their_randomizer = &their.randomizer_v[i]; // panics if len < N
        let their_phi_proof0 = &their.phi_proof0_v[i]; // panics if len < N
        let their_phi_proof1 = &their.phi_proof1_v[i]; // panics if len < N
```

**Round 3 (Spec 3.5) — private scalar shares, lines 400–410:**
```rust
for (_, (a_j_i_v, b_j_i_v)) in recv_from_others::<(Vec<SerializableScalar<C>>, Vec<SerializableScalar<C>>)>(...).await? {
    for i in 0..N {
        let a_j_i = &a_j_i_v[i]; // panics if len < N
        let b_j_i = &b_j_i_v[i]; // panics if len < N
```

**Round 4 (Spec 4.1) — `big_c_j_v` and dlogeq proofs, lines 464–475:**
```rust
for (from, (big_c_j_v, their_phi_proofs)) in recv_from_others::<(Vec<CoefficientCommitment>, Vec<dlogeq::Proof<C>>)>(...).await? {
    for i in 0..N {
        let big_c_j = big_c_j_v[i].value();       // panics if len < N
        let their_phi_proof = &their_phi_proofs[i]; // panics if len < N
```

**Round 5 (Spec 5.1) — `hat_big_c` points and dlog proofs, lines 581–591:**
```rust
for (from, (their_hat_big_c_i_points, their_phi_proofs)) in recv_from_others::<(Vec<CoefficientCommitment>, Vec<dlog::Proof<C>>)>(...).await? {
    for i in 0..N {
        let their_hat_big_c = their_hat_big_c_i_points[i].value(); // panics if len < N
        let their_phi_proof = &their_phi_proofs[i];                 // panics if len < N
```

**Round 5 (Spec 5.5) — `c_j_i_v` scalars, lines 626–631:**
```rust
for (_, c_j_i_v) in recv_from_others::<Vec<SerializableScalar<C>>>(&chan, wait6, &participants, me).await? {
    for i in 0..N {
        let c_j_i = c_j_i_v[i].0; // panics if len < N
```

The `PolynomialCommitmentsMessageMany` struct derives `Deserialize` with no custom length enforcement:

```rust
#[derive(Serialize, Deserialize)]
struct PolynomialCommitmentsMessageMany {
    big_e_v: Vec<PolynomialCommitment>,
    big_f_v: Vec<PolynomialCommitment>,
    big_l_v: Vec<PolynomialCommitment>,
    randomizer_v: Vec<Randomness>,
    phi_proof0_v: Vec<dlog::Proof<Secp256K1Sha256>>,
    phi_proof1_v: Vec<dlog::Proof<Secp256K1Sha256>>,
}
```

The degree check at lines 343–351 that validates polynomial lengths is reached only after the indexing at lines 337–342 has already succeeded — it provides no protection against a short outer Vec. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

### Impact Explanation

A Rust index-out-of-bounds access (`vec[i]` where `i >= vec.len()`) causes an immediate, unrecoverable panic. In the context of this library, the panic aborts the current protocol execution for the honest party. Since triple generation is a mandatory prerequisite for OT-based ECDSA presigning and signing, a malicious participant who is part of the signing group can repeatedly trigger this panic every time triple generation is attempted, permanently denying signing capability to all honest parties for as long as the attacker participates.

**Impact: High — Permanent denial of signing for honest parties under valid protocol inputs.** [8](#0-7) 

### Likelihood Explanation

The attacker must be a legitimate participant in the triple generation protocol — no privileged access, no leaked keys, and no cryptographic breaks are required. Sending a MessagePack-encoded message with an empty or short `Vec` is trivial. The attack is repeatable every session. Any single malicious participant among the `N` parties can trigger it.

**Likelihood: High** — the attacker role (malicious participant) is explicitly in scope per `RESEARCHER.md`, and the exploit requires only crafting a short serialized vector. [9](#0-8) 

### Recommendation

Before indexing into any received `Vec` with `[i]` for `i in 0..N`, validate that the vector's length equals `N` and return a `ProtocolError` (not a panic) on mismatch. Concretely:

1. Add a helper that checks all six fields of `PolynomialCommitmentsMessageMany` immediately after deserialization:
   ```rust
   if their.big_e_v.len() != N || their.big_f_v.len() != N
       || their.big_l_v.len() != N || their.randomizer_v.len() != N
       || their.phi_proof0_v.len() != N || their.phi_proof1_v.len() != N
   {
       return Err(ProtocolError::AssertionFailed(format!(
           "message from {from:?} has wrong vector length"
       )));
   }
   ```
2. Apply the same guard to every other `Vec<T>` received from peers before the `for i in 0..N` loop (commitment round, scalar share round, `big_c_j_v`, `hat_big_c_i_points`, `c_j_i_v`).
3. Consider implementing a custom `Deserialize` for `PolynomialCommitmentsMessageMany` that enforces the length invariant at parse time, similar to how `AppId::BorshDeserialize` enforces `MAX_APP_ID_LEN`. [10](#0-9) 

### Proof of Concept

A malicious participant `M` in a triple generation session with honest parties `H1, H2`:

1. `M` participates honestly through Round 1 (commitment broadcast).
2. At Round 2 (Spec 2.7, `wait2`), instead of sending a `PolynomialCommitmentsMessageMany` with `N` elements in each field, `M` sends a message where `big_e_v` is an empty `Vec` (serialized as a zero-length MessagePack array).
3. When `H1` and `H2` call `recv_from_others::<PolynomialCommitmentsMessageMany>` and then execute `their.big_e_v[0]`, Rust panics with `index out of bounds: the len is 0 but the index is 0`.
4. The panic propagates up through the async executor, aborting the protocol for `H1` and `H2`.
5. `M` repeats this every time triple generation is initiated, permanently blocking OT-based ECDSA signing.

The same attack applies at five other receive points in the same function using different short vectors. [11](#0-10)

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L399-412)
```rust
        // Spec 3.5 + 3.6
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L464-475)
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
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L581-591)
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

**File:** RESEARCHER.md (L36-42)
```markdown
## Attacker Profiles You Must Emulate

- External attacker with no privileged keys (default).
- Malicious normal user abusing valid product/protocol flows.
- Malicious API/RPC/web client submitting crafted inputs at scale.
- Malicious peer/integrator/oracle only where that role is reachable without
  privileged assumptions.
```

**File:** src/confidential_key_derivation/app_id.rs (L116-134)
```rust
impl BorshDeserialize for AppId {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let len = u32::deserialize_reader(reader)? as usize;

        if len > MAX_APP_ID_LEN {
            let err_msg =
                format!("AppId length ({len}) exceeds maximum allowed length ({MAX_APP_ID_LEN})");

            let protocol_error = ProtocolError::DeserializationError(err_msg);

            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                protocol_error,
            ));
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        Self::try_from(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
```
