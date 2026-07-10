### Title
Missing Cryptographic Verification of Participant Shares in CKD Coordinator Allows Malicious Participant to Corrupt CKD Output - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function receives `(norm_big_y, norm_big_c)` shares from each participant and accumulates them with no cryptographic verification. A malicious participant can substitute arbitrary group elements for their honest contribution, causing the coordinator to produce and accept a corrupted `CKDOutput` without any error.

### Finding Description
In `do_ckd_coordinator` (lines 35–57 of `src/confidential_key_derivation/protocol.rs`), the coordinator computes its own share and then receives shares from every other participant, summing them unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

The honest contribution from participant `i` is computed in `compute_signature_share` as:

- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk, app_id) + y_i · app_pk)` [2](#0-1) 

The coordinator holds each participant's public key share (from DKG) and the public parameters `app_pk` and `H(pk, app_id)`, which are sufficient to construct a consistency check. However, no such check is performed. The received `(norm_big_y, norm_big_c)` pair is accepted and added to the running sum regardless of its content.

This is structurally analogous to the reported ERC-4626 slippage issue: just as `deposit`/`mint` accept whatever share count the vault computes without a caller-specified lower bound, `do_ckd_coordinator` accepts whatever group elements a participant sends without a protocol-level validity bound. In both cases the honest party has no mechanism to detect or reject an adversarially chosen output before it is committed.

### Impact Explanation
A single malicious participant (one who holds a legitimate DKG key share) can send an arbitrary pair `(big_y', big_c')` instead of their correct contribution. The coordinator sums this into the final `CKDOutput` and returns it as a successful result. Because the coordinator is the only party that sees the aggregated output, all downstream consumers of the `CKDOutput` (e.g., TEE applications calling `unmask`) will silently operate on a corrupted value. The derived confidential key will differ from the intended `msk · H(pk, app_id)`, rendering it either unusable or, in a targeted attack, biased toward an attacker-chosen value.

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

### Likelihood Explanation
Any participant who has completed DKG and holds a valid signing share is a valid attacker. No additional privilege is required beyond participation in the CKD round itself. The attack requires only that the participant deviate from the protocol by sending an arbitrary `CKDOutput` message — a single network message substitution. There is no threshold tolerance in the CKD protocol: all `N` participants must contribute, so even one malicious participant out of `N` is sufficient to corrupt the output.

### Recommendation
Add a zero-knowledge proof of correct share formation to each participant's message. Concretely, each participant should prove in zero knowledge that their sent `(norm_big_y, norm_big_c)` is of the form `(λ_i · y_i · G, λ_i · (x_i · H(pk, app_id) + y_i · app_pk))` for some scalar `y_i`, using the publicly known `x_i · G2` (the participant's public key share from DKG) as a commitment. The coordinator must verify all proofs before accumulating any share. Alternatively, a Pedersen-commitment-based consistency check binding `norm_big_y` and `norm_big_c` to the participant's known public share can be used.

### Proof of Concept
1. Alice, Bob, and Charlie complete DKG and hold valid signing shares. Alice is the coordinator.
2. Bob is malicious. Instead of calling `compute_signature_share` and sending the result, Bob sends `(ElementG1::identity(), ElementG1::identity())` (or any arbitrary pair) to Alice.
3. Alice's `do_ckd_coordinator` loop executes:
   ```rust
   norm_big_y += participant_output.big_y(); // adds identity, no error
   norm_big_c += participant_output.big_c(); // adds identity, no error
   ``` [3](#0-2) 
4. Alice produces `CKDOutput::new(norm_big_y, norm_big_c)` where `norm_big_y` and `norm_big_c` are missing Bob's Lagrange-weighted contribution.
5. The returned `CKDOutput` is accepted without error. Any call to `ckd_output.unmask(app_sk)` yields a key that differs from the intended `msk · H(pk, app_id)`, silently corrupting the confidential key derivation for all downstream TEE consumers.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L48-57)
```rust
    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L165-181)
```rust
    let big_y = ElementG1::generator() * y.0;

    // H(pk || app_id) when H is a random oracle
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;

    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
```
