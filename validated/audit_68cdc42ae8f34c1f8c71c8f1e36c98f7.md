### Title
Single Malicious Participant Can Force `ZeroScalar` Abort in `do_presign` via Rushing-Adversary `w_p` Manipulation — (`src/ecdsa/robust_ecdsa/presign.rs`)

---

### Summary

A single malicious participant can act as a rushing adversary in Round 2 of `do_presign`, observe all honest participants' `w_i` broadcasts, compute a crafted `w_p` that drives the Lagrange interpolation of all `2t+1` shares to exactly zero, and send it. Every honest party then hits the `ZeroScalar` guard at line 246 and aborts — before the `W == g^w` consistency check at line 302 is ever evaluated. The attack is repeatable on every presign attempt, constituting permanent denial of signing.

---

### Finding Description

**Step 1 — No commitment to `w_i` before reveal.**

Each honest participant computes `w_me = a_me * k_me + b_me` and immediately broadcasts it via `send_many` with no prior hash commitment or ZK proof: [1](#0-0) 

The `W_i = R^{a_i}` value sent in the same message is a commitment to `a_i` given `R`, but it is **not** a commitment to `w_i`. Nothing binds `w_i` to `W_i` before the value is revealed.

**Step 2 — Rushing adversary can observe before sending.**

The honest implementation calls `send_many` before entering the `recv` loop: [2](#0-1) 

A malicious participant is not bound to this ordering. They can skip their own `send_many`, drain all `2t` honest `w_i` broadcasts from the channel, then compute and send a crafted `w_p`. The honest parties are blocked in their `recv` loop waiting for the malicious participant's message, so they will accept it whenever it arrives.

**Step 3 — Linear equation gives exact `w_p`.**

The interpolation at zero is:

```
w = Σ_i  λ_i(P) · w_i   (over all 2t+1 participants)
```

The malicious participant solves:

```
w_p = ( 0 − Σ_{i≠p} λ_i · w_i ) / λ_p
```

This is a single field division — always solvable since `λ_p ≠ 0` for any participant in the set.

**Step 4 — `ZeroScalar` fires before the consistency check.**

After collecting all shares, the code interpolates `w` and immediately checks: [3](#0-2) 

The `W == g^w` check that would detect the inconsistency (fake `w_p` vs. honest `W_p = R^{a_p}`) is at lines 302–311: [4](#0-3) 

Because `ZeroScalar` is returned at line 247, execution **never reaches** line 302. The consistency check is structurally bypassed.

---

### Impact Explanation

Every honest party aborts with `ProtocolError::ZeroScalar`. The malicious participant can repeat this on every presign invocation, since the attack requires only observing the current round's `w_i` values and solving one field equation. No presignature is ever produced, so no threshold signature can be generated. This matches the **High** impact category: permanent denial of signing for honest parties under valid protocol inputs.

---

### Likelihood Explanation

The attack requires only that the malicious participant controls their own protocol implementation (standard adversarial assumption in threshold protocols). No cryptographic assumption is broken. The computation is trivial (one Lagrange interpolation inversion). The protocol enforces `N = 2t+1` exactly: [5](#0-4) 

This means even with `t=1` (three participants, one malicious), the attack works with a single corrupted party.

---

### Recommendation

Introduce a **commitment-then-reveal** scheme for `w_i` before Round 2 opens. Each participant should broadcast `H(w_i || nonce_i)` in a prior sub-round, then reveal `(w_i, nonce_i)` simultaneously. This prevents a rushing adversary from choosing `w_p` adaptively after seeing honest values. Alternatively, restructure the check ordering so the `W == g^w` consistency check (which uses only the honest `W_i = R^{a_i}` values and is independent of the fake `w_p`) executes **before** the `ZeroScalar` guard — this would catch the inconsistency and attribute blame to the malicious participant rather than silently aborting all honest parties.

---

### Proof of Concept

```
Setup: N=3, t=1. Participants: P1 (honest), P2 (honest), P3 (malicious).
Lagrange coefficients at 0 for identifiers (id1, id2, id3): λ1, λ2, λ3.

Round 1: All participants exchange polynomial evaluations honestly.

Round 2 (attack):
  P1 sends (R1, w1) — honest.
  P2 sends (R2, w2) — honest.
  P3 delays send, receives w1 and w2, then computes:
    w3_fake = (0 − λ1·w1 − λ2·w2) / λ3
  P3 sends (R3_honest, w3_fake).

Round 3 (all honest parties):
  w = λ1·w1 + λ2·w2 + λ3·w3_fake
    = λ1·w1 + λ2·w2 + (0 − λ1·w1 − λ2·w2)
    = 0
  → ProtocolError::ZeroScalar returned at line 246.
  → Line 302 (W == g^w check) never reached.
  → Presign aborted for P1 and P2.
```

Fuzz variant: iterate random honest `(w1, w2)` values, assert that computing `w3_fake` as above and running the interpolation always yields `w = 0` and `ProtocolError::ZeroScalar` from the perspective of honest participants.

### Citations

**File:** src/ecdsa/robust_ecdsa/presign.rs (L75-79)
```rust
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during presigning must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L147-168)
```rust
    let w_me = shares.a() * shares.k() + shares.b();

    // Step 2.5
    // Send and receive
    let wait_round_2 = chan.next_waitpoint();
    chan.send_many(wait_round_2, &(&big_r_me, &SigningShare::<C>::new(w_me)))?;

    // Store the sent items
    let mut signingshares_map = ParticipantMap::new(&participants);
    let mut verifyingshares_map = ParticipantMap::new(&participants);
    signingshares_map.put(me, SerializableScalar(w_me));
    verifyingshares_map.put(me, big_r_me);

    // Round 3
    // Receive and interpolate
    while !signingshares_map.full() {
        // Step 3.1
        let (from, (big_r_p, w_p)): (_, (_, SigningShare<C>)) = chan.recv(wait_round_2).await?;
        // collect big_r_p and w_p in maps that will be later ordered
        // if the sender has already sent elements then put will return immediately
        signingshares_map.put(from, SerializableScalar(w_p.to_scalar()));
        verifyingshares_map.put(from, big_r_p);
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L242-248)
```rust
    let w = Polynomial::eval_interpolation(w_2tp1_identifiers, w_2tp1_verifying_shares, None)?;

    // Step 3.6
    // check w is non-zero
    if w.0.is_zero().into() {
        return Err(ProtocolError::ZeroScalar);
    }
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
