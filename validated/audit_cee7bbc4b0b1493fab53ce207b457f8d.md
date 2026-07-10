Looking at the full aggregation path in `do_ckd_coordinator` and the absence of any input validation on received participant outputs.

### Title
Malicious Participant Can Corrupt CKD Aggregation by Sending G1 Identity Points — (`src/confidential_key_derivation/protocol.rs`)

### Summary

`do_ckd_coordinator` aggregates participant-supplied `(norm_big_y, norm_big_c)` pairs with no validation. A malicious participant can send the G1 identity point for both fields, silently removing their secret-share contribution from the Lagrange sum, causing `CKDOutput::unmask` to return a value that is not `msk·H(pk‖app_id)`.

### Finding Description

In `do_ckd_coordinator`, the coordinator receives a `CKDOutput` from every other participant and unconditionally adds the two group elements into running accumulators: [1](#0-0) 

`recv_from_others` only enforces that each participant sends exactly one message; it performs no content validation: [2](#0-1) 

`CKDOutput::new` stores whatever values it receives without any checks: [3](#0-2) 

There is no proof-of-knowledge, commitment binding, or identity-point rejection anywhere in the CKD aggregation path.

### Impact Explanation

The honest aggregation invariant requires:

```
C = Σ_i λ_i·(x_i·H(pk‖app_id) + app_pk·y_i)
  = msk·H(pk‖app_id) + (Σ_i λ_i·y_i)·app_pk
```

so that `unmask(app_sk) = C − app_sk·Y = msk·H(pk‖app_id)`.

If malicious participant j sends `(G1::identity(), G1::identity())`:

- `Y' = Σ_{i≠j} λ_i·y_i·G`  
- `C' = Σ_{i≠j} λ_i·(x_i·H(pk‖app_id) + app_pk·y_i)`

The `y`-masking terms still cancel, but the secret-share term `λ_j·x_j·H(pk‖app_id)` is permanently absent:

```
unmask(app_sk) = C' − app_sk·Y' = Σ_{i≠j} λ_i·x_i·H(pk‖app_id) ≠ msk·H(pk‖app_id)
```

The coordinator returns this corrupted value as `Some(ckd_output)` with no error: [4](#0-3) 

### Likelihood Explanation

Any participant in the CKD protocol controls the message they send to the coordinator. The channel is private (point-to-point), so no other participant can detect the substitution. The attack requires only the ability to participate in the protocol — no cryptographic assumption needs to be broken.

### Recommendation

Before adding a participant's contribution, the coordinator must validate it. At minimum:

1. **Reject identity points**: check `!participant_output.big_y().is_identity()` and `!participant_output.big_c().is_identity()`.
2. **Require a proof of correct formation**: each participant should attach a zero-knowledge proof (e.g., a Schnorr PoK for `y_i` and a DLEQ proof tying `big_y_i` and the `y_i·app_pk` component of `big_c_i`) so the coordinator can verify the contribution is well-formed before aggregating.

### Proof of Concept

```rust
// Malicious participant sends identity for both fields
let malicious_output = CKDOutput::new(
    G1Projective::identity(),  // norm_big_y = 0
    G1Projective::identity(),  // norm_big_c = 0
);
// Coordinator adds these (no-ops in G1) → missing λ_j·x_j·H(pk‖app_id)
// unmask(app_sk) ≠ msk·H(pk‖app_id)
// verify_signature(...) fails
```

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L56-57)
```rust
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/protocol/helpers.rs (L19-24)
```rust
    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }
```

**File:** src/confidential_key_derivation/mod.rs (L38-40)
```rust
    pub fn new(big_y: ElementG1, big_c: ElementG1) -> Self {
        Self { big_y, big_c }
    }
```
