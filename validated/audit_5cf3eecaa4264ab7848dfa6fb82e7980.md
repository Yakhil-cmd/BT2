### Title
Raw Shamir Shares Used Instead of Lagrange-Weighted Shares in Presignature `sigma_i` Computation — (`File: src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

In `do_presign`, the per-party presignature contribution `sigma_i` is computed using the raw (un-weighted) Shamir shares `private_share` (`x_i`) and `a_i`, instead of their Lagrange-weighted counterparts `x_prime_i = λ_i · x_i` and `a_prime_i = λ_i · a_i`. Because the shares are Shamir (polynomial-evaluation) shares, the sum of raw shares does not equal the secret. The resulting aggregate `Σ sigma_i` is therefore not equal to `k · x`, corrupting every presignature produced by the OT-based ECDSA protocol.

---

### Finding Description

The Cait-Sith presigning protocol requires each party to compute:

```
sigma_i = alpha · x'_i  −  beta · a'_i  +  c_i
```

where `x'_i = λ_i · x_i` and `a'_i = λ_i · a_i` are the Lagrange-linearised shares, so that:

```
Σ_i sigma_i = alpha · x  −  beta · a  +  c
            = (k+a)·x  −  (x+b)·a  +  ab
            = k·x
```

The code in `do_presign` correctly computes the Lagrange-weighted values:

```rust
let a_prime_i = lambda_me * a_i;
let x_prime_i = lambda_me * private_share;
```

and uses them in `alpha_i` and `beta_i` respectively. However, the `sigma_i` line reverts to the raw, un-weighted shares:

```rust
// sigmai = alpha*xi - beta*ai + ci
// Spec 2.7
let sigma_i = alpha * private_share - (beta * a_i - c_i);
```

`private_share` is the raw Shamir share `x_i` (not `x'_i`), and `a_i` is the raw triple share (not `a'_i`). For Shamir shares, `Σ x_i ≠ x` and `Σ a_i ≠ a`, so `Σ sigma_i ≠ k·x`. The presignature is therefore cryptographically invalid for any participant set with more than one party. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

Every invocation of the OT-based ECDSA presign protocol produces a `sigma_i` that, when aggregated across all parties, does not equal `k · x`. The downstream signing step will produce an `s` value that fails standard ECDSA verification. No valid threshold signature can be produced. This is a permanent, unconditional corruption of presign outputs for all honest parties running the OT-based ECDSA scheme.

**Matched impact:** *High — Corruption of presign outputs so honest parties accept unusable cryptographic outputs.*

---

### Likelihood Explanation

The bug is triggered on every execution of the OT-based ECDSA presign protocol with two or more participants (the only supported configuration). No special attacker action is required; the miscalculation is structural. Any caller of the public `presign` API will encounter it.

---

### Recommendation

Replace the raw shares in the `sigma_i` computation with their Lagrange-weighted counterparts that are already computed earlier in the function:

```rust
// Correct: use Lagrange-weighted shares x'_i and a'_i
let sigma_i = alpha * x_prime_i - (beta * a_prime_i - c_i);
```

This matches the Cait-Sith specification and ensures `Σ sigma_i = k · x`.

---

### Proof of Concept

Let `n = 2` parties with Shamir threshold 2. Party 1 has identifier scalar `id_1`, party 2 has `id_2`.

- Lagrange coefficients: `λ_1 = id_2 / (id_2 − id_1)`, `λ_2 = id_1 / (id_1 − id_2)`
- Raw shares: `x_1, x_2` with `λ_1·x_1 + λ_2·x_2 = x` (the private key)
- `x_1 + x_2 ≠ x` in general (Shamir, not additive)

With the buggy code:
```
Σ sigma_i = alpha·(x_1 + x_2) − beta·(a_1 + a_2) + (c_1 + c_2)
          = alpha·(x_1+x_2) − beta·(a_1+a_2) + c
```

Since `x_1 + x_2 ≠ x` and `a_1 + a_2 ≠ a`, this is not `k·x`, and the resulting ECDSA signature `s` will fail verification against the public key `X = x·G`. [1](#0-0) [3](#0-2)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L93-103)
```rust
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;

    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L134-185)
```rust
    // alphai = ki' + ai'
    // Spec 2.1
    let alpha_i: Scalar = k_prime_i + a_prime_i;
    // betai = xi' + bi'
    let beta_i: Scalar = x_prime_i + b_prime_i;

    // Send alphai and betai
    // Spec 2.2
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &(alpha_i, beta_i))?;

    // Receive and compute alpha = SUM_j alphaj
    // Receive and compute beta = SUM_j betaj
    // Spec 2.3
    let mut alpha = alpha_i;
    let mut beta = beta_i;

    for (_, (alpha_j, beta_j)) in
        recv_from_others::<(Scalar, Scalar)>(&chan, wait1, &participants, me).await?
    {
        // Spec 2.4
        alpha += alpha_j;
        beta += beta_j;
    }

    // alpha*G =?= K + A
    // beta*G =?= X + B
    // Spec 2.5
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }

    // Compute R = 1/e * D
    // Spec 2.6
    let e_inv: Option<Scalar> = e.invert().into();
    let e_inv =
        e_inv.ok_or_else(|| ProtocolError::AssertionFailed("failed to invert kd".to_string()))?;
    let big_r = (big_d * e_inv).into();

    // sigmai = alpha*xi - beta*ai + ci
    // Spec 2.7
    let sigma_i = alpha * private_share - (beta * a_i - c_i);

    Ok(PresignOutput {
        big_r,
        k: k_i,
        sigma: sigma_i,
    })
```
