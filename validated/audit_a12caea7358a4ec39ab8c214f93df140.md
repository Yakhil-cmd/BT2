### Title
Missing Bounds Check on Participant-Controlled Vector Length Causes Panic in Triple Generation — (`File: src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

---

### Summary

In `do_generation_many`, multiple locations receive a `Vec` from a remote participant and immediately index into it with `[i]` (where `i` ranges from `0..N`) without first verifying that the received vector has at least `N` elements. In Rust, an out-of-bounds index panics, crashing the honest participant's triple generation task. A single malicious participant can exploit this to permanently deny OT-based ECDSA triple generation — and therefore signing — for all honest parties.

---

### Finding Description

The function `do_generation_many<const N: usize>` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs` receives several `Vec`-typed messages from other participants and indexes into them with the compile-time constant `N` as the upper bound. No length check is performed before the indexing.

**Instance 1 — commitment round (lines 180–183):**

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]); // panics if commitments.len() < N
}
``` [1](#0-0) 

**Instance 2 — polynomial commitments round (lines 335–342):**

```rust
for i in 0..N {
    let their_big_e = &their.big_e_v[i];   // panics if big_e_v.len() < N
    let their_big_f = &their.big_f_v[i];
    let their_big_l = &their.big_l_v[i];
    let their_randomizer = &their.randomizer_v[i];
    let their_phi_proof0 = &their.phi_proof0_v[i];
    let their_phi_proof1 = &their.phi_proof1_v[i];
``` [2](#0-1) 

**Instance 3 — private share round (lines 406–410):**

```rust
for i in 0..N {
    let a_j_i = &a_j_i_v[i];  // panics if a_j_i_v.len() < N
    let b_j_i = &b_j_i_v[i];
    a_i_v[i] += &a_j_i.0;
    b_i_v[i] += &b_j_i.0;
}
``` [3](#0-2) 

**Instance 4 — dlogeq proof round (lines 470–475):**

```rust
for i in 0..N {
    let big_c_j = big_c_j_v[i].value();       // panics if big_c_j_v.len() < N
    let their_phi_proof = &their_phi_proofs[i];
``` [4](#0-3) 

**Instance 5 — hat_big_c round (lines 589–591):**

```rust
for i in 0..N {
    let their_hat_big_c = their_hat_big_c_i_points[i].value(); // panics if len < N
    let their_phi_proof = &their_phi_proofs[i];
``` [5](#0-4) 

**Instance 6 — final c_j_i round (lines 626–631):**

```rust
for (_, c_j_i_v) in recv_from_others::<Vec<SerializableScalar<C>>>(...).await? {
    for i in 0..N {
        let c_j_i = c_j_i_v[i].0;  // panics if c_j_i_v.len() < N
``` [6](#0-5) 

The `PolynomialCommitmentsMessageMany` struct that carries the vectors in Instance 2 is deserialized directly from the wire with no field-length enforcement: [7](#0-6) 

Contrast this with `AppId::deserialize_reader`, which explicitly validates the length field before allocating: [8](#0-7) 

No equivalent guard exists anywhere in `do_generation_many` before the `[i]` accesses.

---

### Impact Explanation

A malicious participant sends any of the above messages with a `Vec` whose length is less than `N`. The honest participant's async task panics at the first `[i]` access where `i >= received_len`. Because the panic unwinds the entire `do_generation_many` future, the honest participant's triple generation protocol terminates with an error. Without triples, OT-based ECDSA presigning and signing cannot proceed. A persistent malicious participant can repeat this at every protocol invocation, permanently denying triple generation — and therefore signing — for all honest parties.

**Matched impact:** *High: Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions.*

---

### Likelihood Explanation

Any participant in the triple generation session is a valid attacker. The protocol explicitly models malicious participants (the `max_malicious` parameter). Crafting a short `Vec` requires no cryptographic capability — only the ability to send a message, which every participant already has. The attack is deterministic and requires a single malformed message per round.

---

### Recommendation

Before the `for i in 0..N` loop at each receive site, validate that the received vector has exactly `N` elements and return a `ProtocolError` if not:

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
if commitments.len() != N {
    return Err(ProtocolError::AssertionFailed(format!(
        "commitments from {from:?} has wrong length: expected {N}, got {}",
        commitments.len()
    )));
}
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]);
}
```

Apply the same pattern to every `Vec` field of `PolynomialCommitmentsMessageMany` and to every other received `Vec` that is subsequently indexed by `i in 0..N`.

---

### Proof of Concept

1. Instantiate `generate_triple_many::<N>` with `N > 1` and at least two participants.
2. Have the malicious participant's protocol implementation send, at the commitment round (`wait0`), a `Vec<Commitment>` of length `0` (or any length `< N`) instead of the expected `N` commitments.
3. The honest participant's `do_generation_many` future reaches `commitments[0]` with an empty vector and panics, terminating the protocol with an error.
4. Repeat for every subsequent round to prevent any successful triple generation.

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L400-411)
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L626-631)
```rust
    for (_, c_j_i_v) in
        recv_from_others::<Vec<SerializableScalar<C>>>(&chan, wait6, &participants, me).await?
    {
        for i in 0..N {
            let c_j_i = c_j_i_v[i].0;
            c_i_v[i] += c_j_i;
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
