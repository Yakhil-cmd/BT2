Looking at the full `do_presign` flow in `src/ecdsa/robust_ecdsa/presign.rs` to trace whether any guard catches a corrupted `w_me` before step 3.12.

### Title
Malicious Participant Can Abort Presign for All Honest Parties by Sending Corrupted `w_me` in Round 2 — (`src/ecdsa/robust_ecdsa/presign.rs`)

---

### Summary

A single malicious participant can permanently abort every presign session by broadcasting a crafted `w_me' = w_me + delta` (delta ≠ 0) in round 2. Because no per-party commitment or proof binds `w_i` to the party's `R_i` and `a_i` shares before the final `W == g^w` check at step 3.12, the corrupted scalar propagates undetected through `eval_interpolation`, causing the check to fail for every honest party.

---

### Finding Description

**Protocol context (N = 2t+1 enforced):**

`presign()` enforces `participants.len() == 2*max_malicious+1` at initialization: [1](#0-0) 

**Round 2 — honest computation and broadcast:**

Each party computes `w_me = a_me * k_me + b_me` and broadcasts it alongside `R_me`: [2](#0-1) 

**Round 3 — unchecked receipt of `w_p`:**

Received `w_p` values are stored directly into `signingshares_map` with no validation against `R_p`, `a_p`, or any commitment: [3](#0-2) 

**Step 3.5 — scalar interpolation of `w` from all 2t+1 values:**

`w` is interpolated from all 2t+1 `w_i` values. If one `w_i` is corrupted by delta, the result is `w_true + delta * L_me(0)`: [4](#0-3) 

**Steps 3.7–3.10 — `W` computed from `W_i = R^{a_i}` (unaffected by corrupted `w_me`):**

Each party computes `W_me = R^{a_me}` using their own honest `a_me`. The malicious party also computes this correctly (they know their own `a_me`). So `W = g^{a*k}` is correct: [5](#0-4) 

**Step 3.12 — the only check, which now fails:**

`W = g^{a*k}` (correct) but `g^w = g^{a*k + delta*L_me(0)}` (wrong). The check fails and every honest party returns `Err(AssertionFailed)`: [6](#0-5) 

**Why the existing checks do not catch this:**

- **Step 3.2 (R_i exponent interpolation check):** Validates that `R_i = g^{k_i}` values lie on a degree-t polynomial. This checks `k_i` shares only, not `w_i`.
- **Steps 3.9–3.11 (W_i exponent interpolation check):** Validates that `W_i = R^{a_i}` values lie on a degree-t polynomial. This checks `a_i` shares only, not `w_i`.
- **No commitment or ZK proof** binds `w_i` to `(R_i, a_i)` at any point before step 3.12.

The `w_i` values are pure scalars accepted on faith. The `W == g^w` check is the only guard, and it fires only after all parties have already committed to their `W_me` values.

---

### Impact Explanation

With N=2t+1 (the only allowed configuration), a single malicious participant (t=1, N=3 minimum) can abort every presign session indefinitely. Since presign is a prerequisite for signing, this constitutes **permanent denial of signing** for all honest parties. The attacker does not need to break any cryptographic assumption — they only need to add a nonzero scalar to their `w_me` broadcast.

---

### Likelihood Explanation

Any participant who has completed round 1 (received their private shares) can execute this attack. It requires no special position (coordinator, first party, etc.) and no prior knowledge beyond their own shares. The attack is repeatable across every presign invocation.

---

### Recommendation

Bind each `w_i` to the corresponding `R_i` and `a_i` before accepting it. The standard approach from [DJNPO20] is to require each party to broadcast a **commitment** to `w_i` (e.g., `g^{w_i}`) alongside `R_i` in round 2, and then verify consistency via the exponent interpolation check:

```
∀ i: g^{w_i} == R^{a_i} * g^{b_i}
```

Since `g^{b_i}` is derivable from the public polynomial commitments to `f_{b_i}`, this check can be performed per-party before `w` is interpolated, allowing honest parties to identify and exclude the malicious sender rather than aborting entirely.

---

### Proof of Concept

Simulation (pseudocode):

```rust
// t=1, N=3
// Party 0 is malicious: sends w_0 + delta instead of w_0
let delta = Scalar::from(42u64); // any nonzero value

// Malicious party intercepts its own send_many at wait_round_2
// and adds delta to w_me before broadcasting

// After round 3:
// - w (interpolated) = a*k + delta * L_0(0)  [wrong]
// - W (exponent interpolation of W_i) = g^{a*k}  [correct]
// - W != g^w  =>  AssertionFailed for all 3 parties
assert!(all_parties_return_err_assertion_failed());
```

### Citations

**File:** src/ecdsa/robust_ecdsa/presign.rs (L74-79)
```rust
    // To prevent split-view attacks documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during presigning must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L145-152)
```rust
    // Step 2.4
    // Compute w_me = a_me * k_me + b_me
    let w_me = shares.a() * shares.k() + shares.b();

    // Step 2.5
    // Send and receive
    let wait_round_2 = chan.next_waitpoint();
    chan.send_many(wait_round_2, &(&big_r_me, &SigningShare::<C>::new(w_me)))?;
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L162-169)
```rust
    while !signingshares_map.full() {
        // Step 3.1
        let (from, (big_r_p, w_p)): (_, (_, SigningShare<C>)) = chan.recv(wait_round_2).await?;
        // collect big_r_p and w_p in maps that will be later ordered
        // if the sender has already sent elements then put will return immediately
        signingshares_map.put(from, SerializableScalar(w_p.to_scalar()));
        verifyingshares_map.put(from, big_r_p);
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L234-242)
```rust
    // Step 3.5
    // polynomial interpolation of w
    let (w_2tp1_identifiers, _) = identifiers
        .split_at_checked(2 * threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough identifiers".to_string()))?;
    let (w_2tp1_verifying_shares, _) = signingshares
        .split_at_checked(2 * threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough verifying shares".to_string()))?;
    let w = Polynomial::eval_interpolation(w_2tp1_identifiers, w_2tp1_verifying_shares, None)?;
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L250-299)
```rust
    // Step 3.7
    // Compute W_me = R^{a_me}
    let big_w_me = CoefficientCommitment::new(big_r.value() * shares.a());
    // Step 3.8
    // Send W_me
    let wait_round_3 = chan.next_waitpoint();
    chan.send_many(wait_round_3, &big_w_me)?;

    // Step 3.9
    // Receive W_i
    let mut wshares_map = ParticipantMap::new(&participants);
    wshares_map.put(me, big_w_me);
    while !wshares_map.full() {
        let (from, big_w_p) = chan.recv(wait_round_3).await?;
        wshares_map.put(from, big_w_p);
    }
    // Compute exponent interpolation checks
    let wshares = wshares_map
        .into_vec_or_none()
        .ok_or(ProtocolError::InvalidInterpolationArguments)?;
    let (threshold_plus1_wshares, _) = wshares
        .split_at_checked(threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough wshares".to_string()))?;

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
