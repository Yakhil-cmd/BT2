Now I have enough context to analyze the full flow. Let me verify the exact check and the `add_shares` function:

### Title
Unverified Zero-Secret Polynomial Invariant for `fb` Enables Permanent Presign DoS — (`src/ecdsa/robust_ecdsa/presign.rs`)

### Summary

A malicious participant can send round-1 `fb` polynomial evaluations derived from a polynomial whose constant term is nonzero. Because no commitment or proof enforces the zero-secret invariant on received shares, the corrupted `b_me` propagates into every honest party's `w_me = a_me * k_me + b_me`. The subsequent `W == g^w` check then fails for **all** parties simultaneously, and since the cheating shares were delivered privately there is no mechanism to identify or exclude the malicious participant. Every honest party aborts with `AssertionFailed`, permanently denying presign.

---

### Finding Description

**Round-1 share generation (honest path)**

Each participant generates five polynomials. Indices 2–4 (`fb`, `fd`, `fe`) are required to have zero constant term: [1](#0-0) 

`zero_secret_polynomial` enforces this only for the *local* polynomial: [2](#0-1) 

**Unvalidated ingestion of received shares**

Evaluations from other participants are received and accumulated with no validation: [3](#0-2) 

`add_shares` is a plain element-wise addition — no commitment check, no Feldman VSS, no zero-knowledge proof: [4](#0-3) 

**Corruption propagates into `w_me`**

After accumulation, each party computes: [5](#0-4) 

If the malicious participant's `fb` has constant term `c ≠ 0`, then `b_sum(0) = c`, so the interpolated scalar `w = a·k + c` instead of `a·k`.

**`W == g^w` check fails for every party**

`W` is computed as the exponent interpolation of `W_i = R^{a_i}`, giving `W = g^{k·a}`. But `w = a·k + c`, so `g^w = g^{a·k+c} ≠ W`: [6](#0-5) 

All parties receive the same broadcast `w_i` values and perform the same interpolation, so all abort with `AssertionFailed`.

**No cheater identification**

The corrupted evaluations were delivered via `chan.send_private`: [7](#0-6) 

There is no Feldman commitment to the constant term of `fb`, no polynomial commitment broadcast, and no accountability mechanism. Honest parties cannot identify the malicious participant and cannot retry without it.

---

### Impact Explanation

A single malicious participant (one of the `t` tolerated) can abort every presign attempt indefinitely. The protocol is parameterized as `N = 2t+1` and is advertised as robust against up to `t` malicious parties, but a single corrupted `fb` share permanently denies presign to all honest parties. This matches **High: Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions**.

---

### Likelihood Explanation

The attack requires controlling exactly one participant — the minimum possible attacker capability in this protocol. No cryptographic assumption needs to be broken; the attacker simply substitutes a polynomial with a nonzero constant term for `fb`. The attack is deterministic and repeatable every presign session.

---

### Recommendation

Enforce the zero-secret invariant on received `fb`, `fd`, `fe` shares using a Feldman VSS commitment scheme:

1. Each participant broadcasts a vector commitment `[fb(0)·G, fb(1)·G, …, fb(2t)·G]` for each zero-secret polynomial before sending private evaluations.
2. Upon receiving a private evaluation `fb_j(i)`, each recipient verifies `fb_j(i)·G == Σ commitment_j[l] · i^l` and that `commitment_j[0] == identity` (zero constant term).
3. Any participant whose commitment fails the check or whose evaluation is inconsistent with the commitment is excluded and the protocol aborts with an identified culprit.

This is the standard Feldman VSS approach used for the `fk` and `fa` polynomials in analogous DKG protocols.

---

### Proof of Concept

```rust
// Simulation: participant 0 sends fb evaluations from a polynomial with constant term 1.
// All other participants are honest.
// Expected: all parties abort with AssertionFailed("Exponent interpolation check failed.").

// In do_presign, replace:
//   zero_secret_polynomial(degree, rng)?  // fb
// with:
//   Polynomial::generate_polynomial(Some(Scalar::ONE), degree, rng)?  // fb with constant=1

// Run the existing test_presign with this substitution for one participant.
// All five participants will return Err(ProtocolError::AssertionFailed(...)).
```

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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L125-127)
```rust
        // send the evaluation privately to participant p
        chan.send_private(wait_round_1, p, &package)?;
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L135-139)
```rust
    for (_, package) in recv_from_others(&chan, wait_round_1, &participants, me).await? {
        // Step 2.2
        // calculate the respective sum of the different shares received from each participant
        shares.add_shares(&package);
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L146-147)
```rust
    // Compute w_me = a_me * k_me + b_me
    let w_me = shares.a() * shares.k() + shares.b();
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L302-311)
```rust
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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L389-394)
```rust
    /// Adds two sets of shares together respectively and puts the result back into self
    pub(crate) fn add_shares(&mut self, shares: &Self) {
        for (share, other_share) in self.0.iter_mut().zip(shares.0.iter()) {
            share.0 += other_share.0;
        }
    }
```
