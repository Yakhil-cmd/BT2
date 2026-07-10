Looking at the presign code carefully to trace whether `fb`, `fd`, and `fe` polynomial share corruption is detectable.

### Title
Undetected Non-Zero Constant Term in `fd`/`fe` Polynomials Corrupts Presign Output and Permanently Denies Signing — (`src/ecdsa/robust_ecdsa/presign.rs`)

---

### Summary

A malicious participant in `do_presign` can substitute a polynomial with a non-zero constant term for `fd` or `fe` (Step 1.2). Because the presign protocol performs **no commitment or consistency check** on the `d` or `e` share streams, the corruption propagates silently into every honest participant's `PresignOutput`. The resulting presignature is cryptographically unusable: the signing phase always fails signature verification, permanently denying signing for all honest parties.

---

### Finding Description

**Protocol intent (Step 1.2):**

Each participant is required to generate `fb`, `fd`, `fe` as degree-`2t` polynomials whose constant term is exactly zero, via `zero_secret_polynomial`: [1](#0-0) [2](#0-1) 

The invariant `D(0) = E(0) = 0` is essential for the final signature equation to hold.

**What a malicious participant can do:**

A malicious participant `m` replaces `fd_m` (or `fe_m`) with a polynomial whose constant term is `δ ≠ 0`. They send evaluations of this polynomial privately to every other participant. No broadcast or commitment is published for these shares.

**Aggregation (Step 2.2):**

Each honest participant sums all received shares: [3](#0-2) 

The aggregate `d_i = Σ_j fd_j(i)` and `e_i = Σ_j fe_j(i)`. The aggregate polynomials `D(x)` and `E(x)` now have constant terms `D(0) = δ ≠ 0` and/or `E(0) = ε ≠ 0`.

**Why `fb` corruption IS caught but `fd`/`fe` are NOT:**

The only cryptographic check that could catch zero-constant-term violations is the `W == g^w` check at Step 3.12: [4](#0-3) 

This check compares:
- `W = R^{A(0)} = g^{k·a}` (exponent-interpolated from `W_i = R^{a_i}`)
- `g^w` where `w = A(0)·K(0) + B(0) = k·a + B(0)`

If `B(0) ≠ 0`, then `g^w = g^{k·a+B(0)} ≠ g^{k·a} = W`, so **`fb` corruption is caught**.

However, `d_i` and `e_i` appear **nowhere** in the `W_i`, `w_i`, or `R_i` computations. They are consumed only at: [5](#0-4) 

There is no commitment, no broadcast, and no cross-check on `d_i` or `e_i` at any point in `do_presign`. The presign protocol returns `Ok(PresignOutput { ... })` with corrupted `alpha` and/or `e` without any error.

**Signing failure:**

In `compute_signature_share`, the signature share is: [6](#0-5) 

The aggregate signature scalar becomes:
```
s = msg_hash · (k⁻¹ + D(0)) + k⁻¹·x·Rx + E(0)
```
instead of the valid `s = msg_hash·k⁻¹ + k⁻¹·x·Rx`. The coordinator's final check: [7](#0-6) 

fails, returning `ProtocolError::AssertionFailed`. Signing is permanently denied for this presignature. Since the presign output is already distributed and consumed, the attack cannot be undone.

---

### Impact Explanation

- **Corruption of presign outputs**: Every honest participant receives and stores a `PresignOutput` with a corrupted `alpha` (if `fd` is attacked) or `e` (if `fe` is attacked). The output passes all presign-phase checks and is accepted as valid.
- **Permanent denial of signing**: Any subsequent signing attempt using this presignature fails at the coordinator's `sig.verify` check. The presignature cannot be repaired; a new presign round must be run, which the attacker can corrupt again.
- **No attribution**: The signing phase aggregates shares without per-participant verification, so the malicious participant cannot be identified.

---

### Likelihood Explanation

Any single malicious participant (out of `2t+1`) can execute this attack. It requires only substituting a non-zero constant in their locally generated polynomial before sending shares — a trivial code modification. The attack is deterministic, always succeeds, and leaves no detectable trace in the presign transcript.

---

### Recommendation

Add Pedersen-style commitments to `fd` and `fe` polynomials. Each participant should broadcast `g^{fd_i(0)}, g^{fd_i(1)}, ..., g^{fd_i(2t)}` (the coefficient commitments) before or alongside the private share distribution. Recipients verify that the received evaluation `fd_j(i)` is consistent with the published commitment, and that the committed constant term is `g^0 = identity`. This is the same pattern already used for `fk` and `fa` via the `R_i` and `W_i` exponent-interpolation checks, and should be extended to `fd` and `fe`.

---

### Proof of Concept

```rust
// Malicious participant substitutes a non-zero constant polynomial for fd.
// In do_presign, replace:
//   zero_secret_polynomial(degree, rng)?  // fd
// with:
//   Polynomial::generate_polynomial(Some(some_nonzero_scalar), degree, rng)?  // fd with δ≠0

// Expected result:
// - do_presign returns Ok(PresignOutput { alpha: c_me + d_me_shifted, ... })
//   for all participants, with no error.
// - Subsequent call to sign(...) returns:
//   Err(ProtocolError::AssertionFailed("signature failed to verify"))
// - The shift in alpha equals δ (the attacker's constant term) weighted by
//   Lagrange coefficients, so the aggregate alpha = k⁻¹ + δ ≠ k⁻¹.
// - Same attack applies to fe: corrupted e shifts the signature scalar
//   by E(0) = ε, causing verification failure.
```

The attack is locally testable by modifying the polynomial array at lines 109–111 of `src/ecdsa/robust_ecdsa/presign.rs` for one participant and running the existing `test_e2e` integration test — it will fail at the signing step with a verification error, confirming the presign output was silently corrupted. [8](#0-7)

### Citations

**File:** src/ecdsa/robust_ecdsa/presign.rs (L102-112)
```rust
    let polynomials = [
        // Step 1.1
        // degree t random secret shares where t is the max number of malicious parties
        Polynomial::generate_polynomial(None, threshold, rng)?, // fk
        Polynomial::generate_polynomial(None, threshold, rng)?, // fa
        // Step 1.2
        // degree 2t zero secret shares where t is the max number of malicious parties
        zero_secret_polynomial(degree, rng)?, // fb
        zero_secret_polynomial(degree, rng)?, // fd
        zero_secret_polynomial(degree, rng)?, // fe
    ];
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L135-138)
```rust
    for (_, package) in recv_from_others(&chan, wait_round_1, &participants, me).await? {
        // Step 2.2
        // calculate the respective sum of the different shares received from each participant
        shares.add_shares(&package);
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L301-311)
```rust
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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L319-330)
```rust
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
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L334-341)
```rust
/// Generates a secret polynomial where the constant term is zero
fn zero_secret_polynomial(
    degree: usize,
    rng: &mut impl CryptoRngCore,
) -> Result<Polynomial, ProtocolError> {
    let secret = Secp256K1ScalarField::zero();
    Polynomial::generate_polynomial(Some(secret), degree, rng)
}
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L159-163)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L179-184)
```rust
    let beta = presignature.beta * big_r_x_coordinate + presignature.e;

    let s_me = msg_hash * presignature.alpha + beta;
    // lambda_i * s_i
    let linearized_s_me = s_me * participants.lagrange::<C>(me)?;
    Ok(SerializableScalar::<C>(linearized_s_me))
```
