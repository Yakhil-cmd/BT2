Based on my full trace of the code, here is my assessment:

---

### Title
Missing Validation of Sender-Controlled `c` Values in `mta_receiver` Allows Malicious Sender to Corrupt Multiplication Triple — (`src/ecdsa/ot_based_ecdsa/triples/mta.rs`)

### Summary

`mta_receiver` accepts the sender's `MTAScalars` message with no cryptographic validation beyond a length check. A malicious sender can send `c[0] = (Scalar::ZERO, Scalar::ZERO)`, causing the receiver to compute `m[0] = -v_0` regardless of the OT choice bit, breaking the `alpha + beta = a * b` invariant and producing a corrupted multiplication triple whose `c` component is silently accepted through presign.

### Finding Description

In `mta_receiver`, the only guard on the received `c` values is:

```rust
if c.len() != tv.len() {
    return Err(...);
}
``` [1](#0-0) 

After that, `m[i]` is computed directly from the untrusted sender values:

```rust
.map(|((t_i, v_i), (c0_i, c1_i))| Scalar::conditional_select(&c0_i.0, &c1_i.0, *t_i) - v_i);
``` [2](#0-1) 

If the sender sends `c[0] = (0, 0)`, then `conditional_select(0, 0, t_0) = 0` for any choice bit, so `m[0] = 0 - v_0 = -v_0`. The correct value should be `delta_0 + a` (if `t_0 = 0`) or `delta_0 - a` (if `t_0 = 1`), derived from the honest sender values:

```rust
SerializableScalar(*v0_i + delta_i + a),
SerializableScalar(*v1_i + delta_i - a),
``` [3](#0-2) 

With `m[0]` corrupted, `beta = chi1 * m[0] + Σ chi_i * m[i]` is wrong, so `alpha + beta ≠ a * b`. [4](#0-3) 

This MTA is called from `multiplication_receiver` to produce the `c` component of the triple: [5](#0-4) 

### Impact Explanation

The corrupted `c_i` share flows into `do_presign` as `args.triple1.0.c`:

```rust
let sigma_i = alpha * private_share - (beta * a_i - c_i);
``` [6](#0-5) 

The two presign consistency checks only verify `alpha` and `beta` (derived from `a` and `b`), **not** `c`:

```rust
if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
    || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
``` [7](#0-6) 

A corrupted `c_i` passes both checks undetected. The honest parties accept a `PresignOutput` with a wrong `sigma_i`, producing an unusable (invalid) signature. This matches **High: Corruption of presign outputs so honest parties accept unusable cryptographic outputs**.

Note: the claim in the question that this "leaks `v_0`" to the sender is incorrect — the sender already holds both `v_0^0` and `v_0^1` as their own OT outputs. The actual impact is solely the triple corruption.

### Likelihood Explanation

Any participant who acts as the MTA sender (role is determined deterministically by `hash(i, me)` vs `hash(i, p)` in `multiplication_many`) can trivially send zeroed `c` values. No cryptographic assumption needs to be broken; it is a single-message substitution over an authenticated private channel. [8](#0-7) 

### Recommendation

Add a consistency check in `mta_receiver` that verifies the received `c` values are well-formed with respect to the OT outputs. The standard approach from HMRT21 is a linear-combination consistency check (the "correlation check" in step 4 of the MTA protocol): the receiver already sends `chi1` and `seed` back to the sender; the sender should return a proof or the receiver should verify that `Σ chi_i * c^{t_i}_i` is consistent with the expected linear combination. Alternatively, the triple generation protocol should include a zero-knowledge proof that `c = a * b` (e.g., a multiplication proof over the polynomial commitments) so that a corrupted triple is rejected before it reaches presign.

### Proof of Concept

```rust
// In mta.rs test module — demonstrates alpha+beta != a*b when c[0]=(0,0)
#[test]
fn test_mta_corrupted_sender() {
    // ... set up honest tv, b, seed as in test_mta ...
    // Malicious sender: override c[0] = (ZERO, ZERO) before sending
    // Assert: alpha + beta != a * b
}
```

The existing `test_mta` harness in `mta.rs` already provides the scaffolding; injecting `(Scalar::ZERO, Scalar::ZERO)` at index 0 of the `MTAScalars` message and asserting `alpha + beta != a * b` directly confirms the invariant break. [9](#0-8)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/mta.rs (L52-56)
```rust
                (
                    SerializableScalar(*v0_i + delta_i + a),
                    SerializableScalar(*v1_i + delta_i - a),
                )
            })
```

**File:** src/ecdsa/ot_based_ecdsa/triples/mta.rs (L97-101)
```rust
    if c.len() != tv.len() {
        return Err(ProtocolError::AssertionFailed(
            "length of c was incorrect".to_owned(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/mta.rs (L102-105)
```rust
    let mut m = tv
        .iter()
        .zip(c.iter())
        .map(|((t_i, v_i), (c0_i, c1_i))| Scalar::conditional_select(&c0_i.0, &c1_i.0, *t_i) - v_i);
```

**File:** src/ecdsa/ot_based_ecdsa/triples/mta.rs (L122-128)
```rust
    let mut beta = chi1
        * m.next().ok_or_else(|| {
            ProtocolError::AssertionFailed("Not enough elements received".to_string())
        })?;
    for (&chi_i, m_i) in chi.iter().zip(m) {
        beta += chi_i * m_i;
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/mta.rs (L176-202)
```rust
    #[test]
    fn test_mta() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let batch_size = BITS + SECURITY_PARAMETER;

        let v: Vec<_> = (0..batch_size)
            .map(|_| {
                (
                    Scalar::generate_biased(&mut rng),
                    Scalar::generate_biased(&mut rng),
                )
            })
            .collect();
        let tv: Vec<_> = v
            .iter()
            .map(|(v0, v1)| {
                let c = Choice::from((rng.next_u64() & 1) as u8);
                (c, Scalar::conditional_select(v0, v1, c))
            })
            .collect();

        let a = Scalar::generate_biased(&mut rng);
        let b = Scalar::generate_biased(&mut rng);
        let (alpha, beta) = run_mta((v, a), (tv, b)).unwrap();

        assert_eq!(a * b, alpha + beta);
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/multiplication.rs (L143-150)
```rust
    let task0 = mta_receiver(chan.child(2), res0, *b_i, seed0);
    let seed1 = precomputed_package.seed1;
    let task1 = mta_receiver(chan.child(3), res1, *a_i, seed1);

    // Step 3
    let (gamma0, gamma1) = futures::future::join(task0, task1).await;

    Ok(gamma0? + gamma1?)
```

**File:** src/ecdsa/ot_based_ecdsa/triples/multiplication.rs (L183-212)
```rust
                // participants.
                if order_key_other.as_ref() < order_key_me.as_ref() {
                    let precomputed_sender_package =
                        MultiplicationSenderRandomPackage::generate_random_package(&mut rng);
                    Box::pin(async move {
                        #[allow(clippy::large_futures)]
                        multiplication_sender(
                            chan,
                            sid_arc[i].as_ref(),
                            &av_iv_arc[i],
                            &bv_iv_arc[i],
                            precomputed_sender_package,
                        )
                        .await
                    })
                } else {
                    let precomputed_receiver_package =
                        MultiplicationReceiverRandomPackage::generate_random_package(&mut rng);
                    Box::pin(async move {
                        multiplication_receiver(
                            chan,
                            sid_arc[i].as_ref(),
                            &av_iv_arc[i],
                            &bv_iv_arc[i],
                            precomputed_receiver_package,
                        )
                        .await
                    })
                }
            };
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L162-168)
```rust
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L177-185)
```rust
    // sigmai = alpha*xi - beta*ai + ci
    // Spec 2.7
    let sigma_i = alpha * private_share - (beta * a_i - c_i);

    Ok(PresignOutput {
        big_r,
        k: k_i,
        sigma: sigma_i,
    })
```
