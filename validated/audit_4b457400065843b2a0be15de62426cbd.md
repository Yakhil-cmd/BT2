### Title
Missing Verification of Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `do_ckd_coordinator` function in the Confidential Key Derivation (CKD) protocol accepts `(big_y, big_c)` contributions from participants and blindly sums them without any cryptographic verification that each contribution is correctly formed. A malicious participant can send arbitrary group elements, corrupting the coordinator's CKD output and causing the TEE to decrypt an incorrect confidential key.

### Finding Description
In `do_ckd_coordinator`, the coordinator collects each participant's share of the ElGamal ciphertext and accumulates them: [1](#0-0) 

The coordinator receives `CKDOutput` tuples `(norm_big_y, norm_big_c)` from every other participant and adds them directly to its own running totals. There is no zero-knowledge proof or consistency check verifying that a participant's submitted `(big_y, big_c)` satisfies the relation:

```
big_y  = y · G
big_c  = x_i · H(pk ‖ app_id) + y · app_pk
```

for the same ephemeral scalar `y` and the participant's actual signing share `x_i`.

The correctly-formed computation each honest participant performs is: [2](#0-1) 

A malicious participant's `do_ckd_participant` path simply calls `compute_signature_share` and sends the result: [3](#0-2) 

Nothing prevents a malicious participant from substituting arbitrary group elements for `norm_big_y` and `norm_big_c` before sending. The coordinator has no mechanism to detect the substitution.

This is directly analogous to the reported `BathToken.rebalance` missing check: just as `rebalance` accepted the underlying token as `filledAssetToRebalance` without a guard, `do_ckd_coordinator` accepts any `(big_y, big_c)` pair without a guard on its cryptographic validity.

### Impact Explanation
The CKD output `(big_Y, big_C)` is an ElGamal encryption of `msk · H(pk ‖ app_id)` under `app_pk`. The TEE decrypts it as:

```
big_C − app_sk · big_Y  =  msk · H(pk ‖ app_id)
```

If a malicious participant substitutes `(big_y', big_c')` for their honest contribution `(λ_j · y_j · G, λ_j · (x_j · H + y_j · app_pk))`, the coordinator accumulates a corrupted ciphertext. The TEE decrypts a value that differs from the true `msk · H(pk ‖ app_id)`, producing an incorrect confidential derived key. All downstream application operations using that key silently operate on wrong key material.

This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable or incorrect cryptographic outputs.**

### Likelihood Explanation
Any single participant in the CKD session can trigger this. No special privilege beyond being a listed participant is required. The attacker only needs to deviate from the protocol by sending crafted group elements instead of the honestly computed share. There is no detection mechanism in the current code.

### Recommendation
Add a zero-knowledge proof of correct formation alongside each participant's `(big_y, big_c)` contribution. Concretely, each participant should prove in zero knowledge that:

1. They know a scalar `y` such that `big_y = y · G`.
2. The same `y` satisfies `big_c − x_i · H(pk ‖ app_id) = y · app_pk` (a Chaum-Pedersen / DLEQ proof over the pair `(G, app_pk)` with common discrete log `y`).

The coordinator must verify these proofs before accumulating any contribution, rejecting and identifying any participant whose proof fails.

### Proof of Concept
A malicious participant `j` sends `(big_y' = identity, big_c' = identity)` to the coordinator instead of their honest share.

The coordinator computes:
```
big_Y_corrupt = Σ_{i≠j} λ_i · y_i · G   (missing λ_j · y_j · G)
big_C_corrupt = (msk − λ_j · x_j) · H(pk ‖ app_id)
              + Σ_{i≠j} λ_i · y_i · app_pk
```

The TEE decrypts:
```
big_C_corrupt − app_sk · big_Y_corrupt
  = (msk − λ_j · x_j) · H(pk ‖ app_id)
```

The TEE silently accepts this as the confidential derived key, but it is missing participant `j`'s secret contribution `λ_j · x_j`, making it an incorrect key. All application secrets derived from it are wrong, and the corruption is undetectable by the TEE or the coordinator.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L26-33)
```rust
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}
```

**File:** src/confidential_key_derivation/protocol.rs (L50-56)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

**File:** src/confidential_key_derivation/protocol.rs (L159-181)
```rust
    // y <- ZZq* , Y <- y * G
    let y = Scalar::random(rng);

    // Ensures the value is zeroized on drop
    let y = Zeroizing::new(super::scalar_wrapper::ScalarWrapper(y));

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
