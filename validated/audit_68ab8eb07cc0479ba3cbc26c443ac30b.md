### Title
Missing Length Validation on Received Vectors Causes Panic in Triple Generation - (File: `src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

### Summary
In `do_generation_many`, received protocol messages contain `Vec`-typed fields that are directly indexed with `[i]` for `i in 0..N` without first verifying that the received vector has at least `N` elements. A malicious participant can send a shorter-than-expected vector, triggering an index-out-of-bounds panic that permanently aborts the Beaver triple generation protocol for all honest parties, denying them the ability to produce OT-based ECDSA presignatures and signatures.

### Finding Description

The vulnerability class from the external report is: **assuming a received quantity equals the expected quantity without verification**. In `do_generation_many` (`src/ecdsa/ot_based_ecdsa/triples/generation.rs`), this pattern appears in three distinct receive steps.

**Step 1 — Commitment receive (lines 180–183):**
```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]); // no length check
}
```
The code assumes `commitments.len() >= N`. A malicious participant sends a `Vec` with fewer than `N` elements; the first `i >= commitments.len()` causes a Rust index-out-of-bounds **panic**.

**Step 2 — Polynomial commitment receive (lines 335–342):**
```rust
for i in 0..N {
    let their_big_e = &their.big_e_v[i];      // no length check
    let their_big_f = &their.big_f_v[i];      // no length check
    let their_big_l = &their.big_l_v[i];      // no length check
    let their_randomizer = &their.randomizer_v[i]; // no length check
    let their_phi_proof0 = &their.phi_proof0_v[i]; // no length check
    let their_phi_proof1 = &their.phi_proof1_v[i]; // no length check
```
`PolynomialCommitmentsMessageMany` is a deserialized struct whose inner `Vec` fields are never length-checked against `N` before indexing.

**Step 3 — Private share receive (lines 406–410):**
```rust
for (_, (a_j_i_v, b_j_i_v)) in recv_from_others::<(Vec<_>, Vec<_>)>(...).await? {
    for i in 0..N {
        let a_j_i = &a_j_i_v[i]; // no length check
        let b_j_i = &b_j_i_v[i]; // no length check
```
Same pattern: received `Vec` lengths are assumed to equal `N`.

The analog to the fee-on-transfer bug is exact: the original code assumed `received_balance == amountIn`; here the code assumes `received_vec.len() == N`. In both cases the assumption is not enforced, and a malicious counterparty can violate it.

### Impact Explanation

Beaver triple generation is a prerequisite for every OT-based ECDSA presignature and signature. A panic in `do_generation_many` terminates the async task for the affected honest party. Because the protocol requires all `N` participants to complete, a single malicious participant aborting one honest party's task causes the entire triple generation round to fail. Honest parties cannot produce presignatures or signatures until a new session is started, and the attacker can repeat the attack in every new session, achieving **permanent denial of signing**.

This matches the allowed impact: **High — Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions.**

### Likelihood Explanation

Any participant in the triple generation session can exploit this. No privileged access, leaked keys, or cryptographic breaks are required. The attacker simply serializes a `Vec` with fewer than `N` elements and sends it at the appropriate waitpoint. The attack is trivially repeatable and requires no coordination.

### Recommendation

Before indexing into any received `Vec` with `[i]` for `i in 0..N`, validate that the vector has exactly `N` elements and return a `ProtocolError` (not a panic) if the check fails. For example:

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
if commitments.len() != N {
    return Err(ProtocolError::AssertionFailed(format!(
        "expected {} commitments from {:?}, got {}",
        N, from, commitments.len()
    )));
}
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]);
}
```

Apply the same guard to `their.big_e_v`, `their.big_f_v`, `their.big_l_v`, `their.randomizer_v`, `their.phi_proof0_v`, `their.phi_proof1_v`, `a_j_i_v`, and `b_j_i_v` before the `for i in 0..N` loops.

### Proof of Concept

1. Participant `P_malicious` joins a triple generation session with `N > 1` honest parties.
2. At `wait0` (commitment round), instead of sending a `Vec` of length `N`, `P_malicious` serializes and sends a `Vec` of length `0` (or any length `< N`).
3. Each honest party receives this message, enters the loop `for i in 0..N`, and attempts `commitments[0]` on an empty vector.
4. Rust's indexing operator panics with `index out of bounds: the len is 0 but the index is 0`.
5. The async task for every honest party that processed the malicious message terminates with a panic, aborting triple generation.
6. The attacker repeats this in every subsequent session, permanently denying signing capability.