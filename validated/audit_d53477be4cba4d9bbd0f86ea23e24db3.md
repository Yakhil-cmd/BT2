### Title
Unverified Participant Contributions in CKD Protocol Allow Any Malicious Participant to Corrupt the Derived Confidential Key - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary
The CKD coordinator aggregates each participant's `(norm_big_y, norm_big_c)` contribution with no cryptographic verification. A single malicious participant can substitute arbitrary group elements, causing the coordinator to reconstruct a wrong confidential key while all honest parties believe the protocol succeeded.

---

### Finding Description

In `do_ckd_coordinator` the coordinator collects every participant's share and blindly adds it to the running totals:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

The honest computation each participant is supposed to perform is:

```rust
let big_y  = ElementG1::generator() * y.0;          // y_i · G
let big_s  = hash_point * private_share.to_scalar(); // x_i · H(pk‖app_id)
let big_c  = big_s + app_pk * y.0;                  // x_i·H + y_i·A
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
``` [2](#0-1) 

There is **no zero-knowledge proof, commitment, or any other check** that the values sent to the coordinator were produced from the participant's actual key share `x_i` and the agreed-upon `app_id`/`app_pk`. The coordinator has no mechanism to distinguish a correctly-formed contribution from an arbitrary pair of group elements.

The analog to the external report is direct: just as Tellor acts as a trusted fallback oracle whose price is accepted without on-chain proof of correctness, each participant's `(norm_big_y, norm_big_c)` is accepted as a trusted input without any proof of correct formation. A malicious participant can cheaply "report" any value they choose, corrupting the aggregate in a single protocol execution.

---

### Impact Explanation

The final CKD output is:

```
big_Y_total = Σ λ_i · y_i · G
big_C_total = Σ λ_i · (x_i · H(pk‖app_id) + y_i · A)
```

`unmask(app_sk)` recovers `big_C_total − app_sk · big_Y_total = msk · H(pk‖app_id)`.

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

**File:** src/confidential_key_derivation/protocol.rs (L160-181)
```rust
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
