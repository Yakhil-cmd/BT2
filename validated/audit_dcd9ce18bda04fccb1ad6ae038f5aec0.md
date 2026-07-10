### Title
Malicious Participant Can Force `ZeroScalar` Abort in Presign via Crafted `w_me` — (`src/ecdsa/robust_ecdsa/presign.rs`)

---

### Summary

A single malicious participant acting as a rushing adversary can compute and broadcast a crafted `w_me` scalar that drives the Lagrange interpolation of `w` at zero to exactly zero, triggering the `ZeroScalar` abort at line 247 for every honest party. No per-share commitment on `w_i` values exists before interpolation, and the only consistency guard (`W == g^w`) is placed after the zero-check and is therefore never reached.

---

### Finding Description

**Round 2 — broadcast of `w_me`:**

Each honest party computes and broadcasts `w_me = a_me * k_me + b_me` together with `R_me = g^{k_me}`. [1](#0-0) 

Received `w_p` values are stored directly into `signingshares_map` with no validation: [2](#0-1) 

**Step 3.5 — scalar interpolation with no per-share guard:**

The protocol takes the first `2t+1` scalar shares and interpolates `w` at zero: [3](#0-2) 

**Step 3.6 — `ZeroScalar` abort:** [4](#0-3) 

**Step 3.12 — the only consistency check, placed too late:**

The check `W == g^w` (which would detect a tampered `w_me` against the independently-computed `W_i = R^{a_i}` shares) is evaluated only after the zero-check: [5](#0-4) 

Because the abort at line 247 fires first, the `W == g^w` guard is never reached when `w = 0`.

**Algebraic attack (rushing adversary):**

Let the `2t+1` participant identifiers be `x_1, …, x_{2t+1}` and their Lagrange coefficients at zero be `λ_1, …, λ_{2t+1}`. The interpolated value is:

```
w = Σ λ_i · w_i
```

A rushing adversary (participant `m`) withholds their Round-2 message, collects all honest `w_i` values, then solves:

```
w_m = −(Σ_{i≠m} λ_i · w_i) / λ_m
```

This is a single field division — no cryptographic assumption is broken. The adversary then broadcasts this crafted `w_m` (paired with their honest `R_m = g^{k_m}`, so the `R`-consistency check at lines 194–213 still passes). Every honest party independently computes `w = 0` and aborts. [6](#0-5) 

---

### Impact Explanation

Every honest party aborts with `ZeroScalar`. The malicious party can repeat this attack on every presign invocation, permanently blocking presignature generation. No party can identify the culprit from the error alone, so exclusion requires an out-of-band mechanism not provided by the library.

**Impact category:** High — Permanent denial of presigning for honest parties under valid protocol inputs.

---

### Likelihood Explanation

Requires only one malicious participant with rushing-adversary capability (standard in threshold-protocol threat models). The computation is a single field inversion and linear combination — trivially automatable. No special privileges, no key material, no cryptographic hardness assumption is needed.

---

### Recommendation

Move the `W == g^w` consistency check (Step 3.12) **before** the `ZeroScalar` check (Step 3.6), or — better — add a per-share commitment on each `w_i` in Round 2. Concretely:

- Each party should broadcast a commitment `C_i = g^{w_i}` alongside `w_i` in Round 2.
- Before interpolation, every party verifies `g^{w_i} == C_i` for each received share.
- A failing check identifies and excludes the malicious party rather than aborting the whole session.

Alternatively, reorder the existing checks so that the `W == g^w` guard fires first; a mismatch then aborts with an `AssertionFailed` that can be attributed to the party whose `W_i` is inconsistent with the interpolated `w`.

---

### Proof of Concept

```rust
// Pseudocode — rushing adversary computes crafted w_m

// 1. Malicious party m delays Round-2 message.
// 2. Collects honest w_i values for all i ≠ m.
// 3. Computes Lagrange coefficients λ_i at zero for all 2t+1 identifiers.
// 4. Solves for w_m:
let w_m = -(sum of λ_i * w_i for i ≠ m) * λ_m.invert();
// 5. Broadcasts (R_m_honest, w_m_crafted).
// 6. Every honest party computes:
//      w = Σ λ_i * w_i = 0
//    and hits:
//      if w.0.is_zero() { return Err(ProtocolError::ZeroScalar); }
// 7. Presign aborts for all honest parties; malicious party is unidentified.
```

### Citations

**File:** src/ecdsa/robust_ecdsa/presign.rs (L147-152)
```rust
    let w_me = shares.a() * shares.k() + shares.b();

    // Step 2.5
    // Send and receive
    let wait_round_2 = chan.next_waitpoint();
    chan.send_many(wait_round_2, &(&big_r_me, &SigningShare::<C>::new(w_me)))?;
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L162-168)
```rust
    while !signingshares_map.full() {
        // Step 3.1
        let (from, (big_r_p, w_p)): (_, (_, SigningShare<C>)) = chan.recv(wait_round_2).await?;
        // collect big_r_p and w_p in maps that will be later ordered
        // if the sender has already sent elements then put will return immediately
        signingshares_map.put(from, SerializableScalar(w_p.to_scalar()));
        verifyingshares_map.put(from, big_r_p);
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L236-242)
```rust
    let (w_2tp1_identifiers, _) = identifiers
        .split_at_checked(2 * threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough identifiers".to_string()))?;
    let (w_2tp1_verifying_shares, _) = signingshares
        .split_at_checked(2 * threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough verifying shares".to_string()))?;
    let w = Polynomial::eval_interpolation(w_2tp1_identifiers, w_2tp1_verifying_shares, None)?;
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L246-248)
```rust
    if w.0.is_zero().into() {
        return Err(ProtocolError::ZeroScalar);
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L303-311)
```rust
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

**File:** src/crypto/polynomials.rs (L139-162)
```rust
    pub fn eval_interpolation(
        identifiers: &[Scalar<C>],
        shares: &[SerializableScalar<C>],
        point: Option<&Scalar<C>>,
    ) -> Result<SerializableScalar<C>, ProtocolError>
    where
        Scalar<C>: ConstantTimeEq,
    {
        let mut interpolation = <C::Group as Group>::Field::zero();
        // raise Error if the lengths are not the same
        // or the number of identifiers (<= 1)
        if identifiers.len() != shares.len() || identifiers.len() <= 1 {
            return Err(ProtocolError::InvalidInterpolationArguments);
        }

        // Compute the Lagrange coefficients in batch
        let lagrange_coefficients = batch_compute_lagrange_coefficients::<C>(identifiers, point)?;

        // Compute y = f(point) via polynomial interpolation of these points of f
        for (lagrange_coefficient, share) in lagrange_coefficients.iter().zip(shares) {
            interpolation = interpolation + (lagrange_coefficient.0 * share.0);
        }

        Ok(SerializableScalar(interpolation))
```
