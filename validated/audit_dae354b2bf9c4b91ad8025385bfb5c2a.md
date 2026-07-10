### Title
Unvalidated Accumulation of `d` and `e` Shares in Robust ECDSA Presign Corrupts Honest Party Outputs Without Detection - (File: src/ecdsa/robust_ecdsa/presign.rs)

### Summary
In `src/ecdsa/robust_ecdsa/presign.rs`, the `do_presign` function accumulates five polynomial share values (`k`, `a`, `b`, `d`, `e`) received from each participant via `shares.add_shares(&package)` without any commitment-based validation. While subsequent interpolation checks protect the `k`, `a`, and `b` shares, the `d` and `e` shares are never verified against any commitment. A malicious participant can inject arbitrary scalar values for `d` or `e` into an honest party's accumulated share, silently corrupting that party's `PresignOutput` (`alpha`, `e`). The honest party accepts the corrupted output with no indication of failure, and the malicious party cannot be identified.

### Finding Description

In Round 1 of `do_presign`, each participant generates five polynomials (`fk`, `fa`, `fb`, `fd`, `fe`) and privately sends their evaluations to every other participant. In Round 2, each honest party accumulates the received evaluations unconditionally:

```rust
// src/ecdsa/robust_ecdsa/presign.rs lines 134–138
for (_, package) in recv_from_others(&chan, wait_round_1, &participants, me).await? {
    // calculate the respective sum of the different shares received from each participant
    shares.add_shares(&package);
}
```

`add_shares` performs a raw field-element addition with no commitment check:

```rust
// src/ecdsa/robust_ecdsa/presign.rs lines 390–394
pub(crate) fn add_shares(&mut self, shares: &Self) {
    for (share, other_share) in self.0.iter_mut().zip(shares.0.iter()) {
        share.0 += other_share.0;
    }
}
```

The subsequent Round 3 checks protect only three of the five shares:

| Share | Protection mechanism |
|-------|---------------------|
| `k` | Exponent interpolation check on `R_i = g^{k_i}` (lines 194–213) |
| `a` | Exponent interpolation check on `W_i = R^{a_i}` (lines 274–291) |
| `b` | Implicit check via `W == g^w` (lines 303–311), since `b(0)` must be 0 |
| **`d`** | **No check** |
| **`e`** | **No check** |

The `d` and `e` shares flow directly into the final output without any verification:

```rust
// src/ecdsa/robust_ecdsa/presign.rs lines 319–330
let alpha_me = c_me + shares.d();   // d is never validated
...
Ok(PresignOutput {
    big_r: big_r.value().to_affine(),
    alpha: alpha_me,
    beta: beta_me,
    c: c_me,
    e: shares.e(),   // e is never validated
})
```

This is structurally identical to the OmoVault inflation pattern: attacker-controlled values (`d_j`, `e_j` sent by malicious participant `j`) are summed into a critical accumulated total (`shares.d()`, `shares.e()`) without validation against any commitment, and the corrupted total is accepted as a valid output.

### Impact Explanation

A malicious participant `M` sends crafted `d` and/or `e` evaluations to honest party `P`. `P` sums them into its local `shares` without any check. `P`'s `PresignOutput` is returned as `Ok(...)` with corrupted `alpha = c_P + d_P_corrupted` and/or corrupted `e`. When `P` uses this presign output in the signing phase, its signature share will be computed from wrong material, causing the signing round to produce an invalid or unusable signature. Because the corruption occurs silently in the presign phase, `M` is never identified as the culprit, and the protocol cannot exclude `M`. As long as `M` remains in the participant set, every presign attempt for `P` can be silently poisoned, constituting a permanent denial of signing for honest parties.

This matches the allowed impact: **High — Corruption of presign outputs so honest parties accept unusable cryptographic outputs**, and **High — Permanent denial of signing for honest parties under valid protocol inputs**.

### Likelihood Explanation

Any single malicious participant in the presign session can trigger this. No special privilege, leaked key, or external assumption is required — the attacker only needs to be one of the `N = 2t+1` participants and send crafted scalar values in Round 1. The attack is trivial to execute and completely undetectable by the honest party.

### Recommendation

Commit polynomial commitments for `fd` and `fe` alongside those for `fk`, `fa`, `fb` in Round 1 (or Round 2 via broadcast), and verify each received `d_j` and `e_j` evaluation against the corresponding commitment before calling `add_shares`. Alternatively, extend the existing exponent-interpolation consistency check to cover `d` and `e` shares, analogous to the `R_i` and `W_i` checks already present for `k` and `a`.

### Proof of Concept

1. Honest parties `P1..P5` run `presign` with `max_malicious = 2` (so `N = 5`).
2. Malicious party `M = P5` intercepts Round 1 and, instead of sending `fd(P1)` and `fe(P1)` to `P1`, sends `fd(P1) + delta` and `fe(P1) + delta` for an arbitrary non-zero scalar `delta`.
3. `P1` receives the package and calls `shares.add_shares(&package)` at line 138 — no error is raised.
4. `P1`'s accumulated `shares.d()` and `shares.e()` are now offset by `delta`.
5. `P1`'s `PresignOutput` is returned with `alpha = c_P1 + (d_P1 + delta)` and `e = e_P1 + delta`.
6. All Round 3 interpolation checks (`R_i`, `W_i`, `W == g^w`) pass because they do not involve `d` or `e`.
7. When `P1` participates in signing with this corrupted presign output, its signature share is computed from wrong `alpha`/`e`, producing an invalid final signature. `M` is never flagged. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/ecdsa/robust_ecdsa/presign.rs (L134-139)
```rust
    // Receive evaluations from all participants
    for (_, package) in recv_from_others(&chan, wait_round_1, &participants, me).await? {
        // Step 2.2
        // calculate the respective sum of the different shares received from each participant
        shares.add_shares(&package);
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L194-213)
```rust
    for (identifier, verifying_share) in identifiers
        .iter()
        .skip(threshold + 1)
        .zip(verifying_shares.iter().skip(threshold + 1))
    {
        // Step 3.2
        // exponent interpolation for (R0, .., Rt; i)
        let big_r_i = PolynomialCommitment::eval_exponent_interpolation(
            threshold_plus1_identifiers,
            threshold_plus1_verifying_shares,
            Some(identifier),
        )?;

        // check the interpolated R values match the received ones
        if big_r_i != *verifying_share {
            return Err(ProtocolError::AssertionFailed(
                "Exponent interpolation check failed.".to_string(),
            ));
        }
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L274-311)
```rust
    for (identifier, wshare) in identifiers
        .iter()
        .skip(threshold + 1)
        .zip(wshares.iter().skip(threshold + 1))
    {
        // exponent interpolation for (W0, .., Wt; i)
        let big_w_i = PolynomialCommitment::eval_exponent_interpolation(
            threshold_plus1_identifiers,
            threshold_plus1_wshares,
            Some(identifier),
        )?;
        // check the interpolated W values match the received ones
        if big_w_i != *wshare {
            return Err(ProtocolError::AssertionFailed(
                "Exponent interpolation check failed.".to_string(),
            ));
        }
    }

    // Step 3.10
    // compute W as exponent interpolation for (W0, .., Wt; 0)
    let big_w = PolynomialCommitment::eval_exponent_interpolation(
        threshold_plus1_identifiers,
        threshold_plus1_wshares,
        None,
    )?;

    // Step 3.12
    // check W == g^w
    if big_w
        .value()
        .ct_ne(&(<Secp256K1Group as Group>::generator() * w.0))
        .into()
    {
        return Err(ProtocolError::AssertionFailed(
            "Exponent interpolation check failed.".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L315-331)
```rust
    let c_me = w.0.invert().unwrap() * shares.a();

    // Step 3.14
    // Some extra computation is pushed in this offline phase
    let alpha_me = c_me + shares.d();

    // Step 3.15
    let x_me = args.keygen_out.private_share.to_scalar();
    let beta_me = c_me * x_me;

    Ok(PresignOutput {
        big_r: big_r.value().to_affine(),
        alpha: alpha_me,
        beta: beta_me,
        c: c_me,
        e: shares.e(),
    })
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L389-394)
```rust
    /// Adds two sets of shares together respectively and puts the result back into self
    pub(crate) fn add_shares(&mut self, shares: &Self) {
        for (share, other_share) in self.0.iter_mut().zip(shares.0.iter()) {
            share.0 += other_share.0;
        }
    }
```
