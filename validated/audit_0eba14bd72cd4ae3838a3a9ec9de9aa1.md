Looking at the CKD protocol in `src/confidential_key_derivation/protocol.rs`, I can identify a valid analog.

---

### Title
Malicious CKD Participant Can Send Unverified Contribution Shares to Corrupt Derived Key Output - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator blindly accumulates `(norm_big_y, norm_big_c)` contributions from every participant with no proof of correctness. Any single malicious participant can substitute arbitrary group elements, causing the coordinator to output a corrupted confidential derived key that honest parties accept as valid.

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's `CKDOutput` and unconditionally adds it to the running sum: [1](#0-0) 

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant computes their contribution as: [2](#0-1) 

```
big_y  = y_i * G
big_s  = x_i * H(pk || app_id)
big_c  = big_s + y_i * app_pk
norm_big_y = lambda_i * big_y
norm_big_c = lambda_i * big_c
```

There is **no zero-knowledge proof** (e.g., Chaum-Pedersen) that the received `(norm_big_y, norm_big_c)` was computed from the participant's actual private share `x_i`. The coordinator has no independent reference to cross-check against — analogous to the GMX adapter trusting `getMinPrice()`/`getMaxPrice()` without verifying against Chainlink.

Compare this with the DKG protocol, which does verify every participant contribution via proof-of-knowledge and commitment hashes before accepting it: [3](#0-2) 

No equivalent verification exists in the CKD path.

### Impact Explanation

A single malicious participant sends `(0, 0)` or any arbitrary `(big_y', big_c')` instead of their correct contribution. The coordinator sums all values including the poisoned one and returns a `CKDOutput` whose `unmask(app_sk)` yields a wrong group element — not `msk * H(pk || app_id)`. Every honest party that receives and uses this output accepts a corrupted confidential derived key. This matches the allowed impact:

> **High: Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation

Any one of the N participants in the CKD session is a sufficient attacker. No special privilege is required beyond being a listed participant. The attack requires sending a single malformed message in round 1 of the protocol — trivially reachable by a library caller who controls one participant's execution.

### Recommendation

Require each participant to accompany their `(norm_big_y, norm_big_c)` with a Chaum-Pedersen discrete-log equality proof demonstrating that:

```
norm_big_c - lambda_i * x_i * H(pk || app_id)  =  (norm_big_y / G) * app_pk
```

i.e., that the same scalar `lambda_i * y_i` was used for both `norm_big_y = lambda_i * y_i * G` and the masking term `lambda_i * y_i * app_pk`. The coordinator must verify this proof before accumulating the contribution, mirroring the proof-of-knowledge checks already present in `do_keyshare` in `src/dkg.rs`.

### Proof of Concept

1. Honest participants P1…P(n-1) compute correct `(norm_big_y_i, norm_big_c_i)` and send them to the coordinator.
2. Malicious participant Pn sends `(ElementG1::identity(), ElementG1::identity())` — the additive identity — instead of their real contribution.
3. The coordinator executes: [4](#0-3) 

   and produces `CKDOutput { big_y, big_c }` where the Pn Lagrange term is missing.
4. `ckd_output.unmask(app_sk)` returns `big_c - app_sk * big_y`, which equals `SUM_{i<n}(lambda_i * x_i * H) ≠ msk * H(pk || app_id)`.
5. The coordinator returns this corrupted output as `Some(ckd_output)` with no error, and honest callers accept it as the valid derived key.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
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

**File:** src/dkg.rs (L452-469)
```rust
        verify_proof_of_knowledge(
            &session_id,
            &mut proof_domain_separator.clone(), // you want to have the same state
            threshold,
            p,
            old_participants.clone(),
            commitment_i,
            proof_i.as_ref(),
        )?;

        // verify that the commitment sent hashes to the received commitment_hash in round 1
        verify_commitment_hash(
            &session_id,
            p,
            &mut commit_domain_separator.clone(), // you want to have the same state
            commitment_i,
            &all_hash_commitments,
        )?;
```
