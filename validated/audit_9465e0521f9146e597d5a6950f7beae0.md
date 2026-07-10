### Title
Unchecked `fd` Share Injection Corrupts `alpha_me` in Presign, Producing Unusable Presign Output — (`src/ecdsa/robust_ecdsa/presign.rs`)

---

### Summary

A malicious participant in the robust ECDSA presign protocol can send an arbitrary scalar as their `fd` polynomial evaluation to any target honest participant. Because no commitment, proof, or consistency check is performed on the `d` shares, the honest participant's accumulated `shares.d()` is attacker-controlled. This corrupts `alpha_me = c_me + shares.d()`, producing a `PresignOutput` that the honest participant accepts as valid but that will cause every subsequent signing attempt to fail.

---

### Finding Description

In `do_presign`, Round 1 generates five polynomials per participant, including `fd` — a degree-2t zero-secret polynomial whose evaluations are sent privately to each other participant: [1](#0-0) 

In Round 2, received packages are accumulated with no validation: [2](#0-1) 

The `add_shares` method is a plain scalar addition with zero checks: [3](#0-2) 

The accumulated `d` share is then used directly to compute `alpha_me`: [4](#0-3) 

The protocol's Round 3 checks validate only `R_i` (via exponent interpolation on `g^{k_i}`) and `W_i` (via exponent interpolation on `R^{a_i}`), plus the `W == g*w` and `w != 0` assertions. **None of these touch the `d` shares.** There is no polynomial commitment, no Pedersen commitment, no zero-knowledge proof, and no consistency check for any `fd_j(i)` value received from another participant. [5](#0-4) [6](#0-5) 

The protocol specification confirms `d_i` is computed as a plain sum with no verification step: [7](#0-6) 

---

### Impact Explanation

A malicious participant sends `fd_attacker(target) + δ` (for any chosen non-zero scalar `δ`) instead of the correct `fd_attacker(target)` to the target honest participant. The target's `d_me` is shifted by `δ`, so:

```
alpha_me = c_me + d_me + δ   (instead of c_me + d_me)
```

The Lagrange-weighted sum during signing becomes:

```
s = Σ λ_i · s_i = s_valid + λ_me · msg_hash · δ
```

This is not a valid ECDSA signature. The coordinator's verification check in `do_sign_coordinator` catches it: [8](#0-7) 

The signing protocol returns `ProtocolError::AssertionFailed`. The honest participant has already accepted and stored a `PresignOutput` with a corrupted `alpha` field — an output that is permanently unusable. Since presignatures must never be reused (per the protocol's own security requirements), the honest participant cannot recover. [9](#0-8) 

---

### Likelihood Explanation

The attack requires only that the adversary be a legitimate participant in the presign session — the minimum possible privilege level. The crafted share is a single scalar value sent over an already-existing private channel. No cryptographic assumption needs to be broken. The attack is deterministic and repeatable: every presign session involving the malicious participant can be sabotaged. With `t` malicious participants (the maximum the protocol tolerates), all `2t+1 - t = t+1` honest participants can be targeted simultaneously, permanently denying signing capability.

---

### Recommendation

Add polynomial commitments for `fd` (and `fe`, `fb`, `fk`, `fa`) in Round 1. Each participant should broadcast `g^{fd_i(0)}, g^{fd_i(1)}, ..., g^{fd_i(2t)}` (the coefficient commitments of their `fd` polynomial) alongside the private shares. Each recipient then verifies that the received scalar `d_{ji}` satisfies `g^{d_{ji}} == Σ_k (g^{coeff_k})^{j^k}` before accumulating it. For `fd`, additionally verify that the constant-term commitment equals the group identity (i.e., `fd_i(0) = 0`). This is the standard VSS (Verifiable Secret Sharing) check used in protocols like Pedersen-VSS.

---

### Proof of Concept

State-test: in a 5-participant presign session with `max_malicious = 2`, intercept the private Round 1 message from participant `P_attacker` to participant `P_target`. Replace the 4th scalar (the `fd` share, index 3) with `fd_attacker(target) + δ` for any non-zero `δ`. Let the presign protocol complete — it will succeed and return a `PresignOutput` to `P_target` with `alpha = c_me + d_me + δ`. Then run the signing protocol. The coordinator's `sig.verify` check will fail, returning `ProtocolError::AssertionFailed("signature failed to verify")`, confirming the presign output is unusable. [10](#0-9)

### Citations

**File:** src/ecdsa/robust_ecdsa/presign.rs (L108-127)
```rust
        // degree 2t zero secret shares where t is the max number of malicious parties
        zero_secret_polynomial(degree, rng)?, // fb
        zero_secret_polynomial(degree, rng)?, // fd
        zero_secret_polynomial(degree, rng)?, // fe
    ];

    // send polynomial evaluations to participants
    let wait_round_1 = chan.next_waitpoint();

    // Step 1.3
    for p in participants.others(me) {
        // Securely send to each other participant a secret share
        let package = polynomials
            .iter()
            .map(|poly| poly.eval_at_participant(p))
            .collect::<Result<Vec<_>, _>>()?;

        // send the evaluation privately to participant p
        chan.send_private(wait_round_1, p, &package)?;
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L130-139)
```rust
    let mut shares = Shares::new(&polynomials, me)?;

    // Round 2
    // Step 2.1
    // Receive evaluations from all participants
    for (_, package) in recv_from_others(&chan, wait_round_1, &participants, me).await? {
        // Step 2.2
        // calculate the respective sum of the different shares received from each participant
        shares.add_shares(&package);
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L193-213)
```rust
    // check that the exponent interpolations match what has been received
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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L317-319)
```rust
    // Step 3.14
    // Some extra computation is pushed in this offline phase
    let alpha_me = c_me + shares.d();
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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L35-44)
```markdown
1. $\bullet$ Each $P_i$ waits to receive $(k_{ji}, a_{ji}, b_{ji}, d_{ji}, e_{ji})$ from each other $P_j$.
2. Each $P_i$ sums the shares received from the participants:

$$
k_i \gets \sum_j k_{ji} \qquad
a_i \gets \sum_j a_{ji} \qquad
b_i \gets \sum_j b_{ji} \qquad
d_i \gets \sum_j d_{ji} \qquad
e_i \gets \sum_j e_{ji}
$$
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L159-163)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/mod.rs (L27-37)
```rust
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize(skip)]
    pub big_r: AffinePoint,

    /// Our secret shares of the nonces.
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}
```
