### Title
Malicious Participant Can Permanently Abort Robust ECDSA Presigning by Sending Invalid W_i Share, Rendering Presignature State Unavailable - (File: src/ecdsa/robust_ecdsa/presign.rs)

---

### Summary

In the Robust ECDSA presigning protocol (`do_presign`), a malicious participant within the `t`-threshold can deliberately send an invalid `W_i` share in Round 3. Because presignatures are explicitly one-time-use, the resulting protocol abort permanently destroys the presignature state. The protocol provides no mechanism to identify the culprit, so the malicious participant can repeat this for every presigning attempt, permanently denying signing for all honest parties.

---

### Finding Description

`do_presign` in `src/ecdsa/robust_ecdsa/presign.rs` executes a 3-round presigning protocol. In Round 3, each participant `P_i` computes `W_i = R^{a_i}` and broadcasts it. The protocol then performs two checks:

**Check 1 – Consistency check (lines 274–291):** For participants at indices `> threshold` (i.e., those NOT in the interpolation basis), the protocol verifies that their `W_j` matches the exponent interpolation from the first `t+1` values:

```rust
for (identifier, wshare) in identifiers
    .iter()
    .skip(threshold + 1)
    .zip(wshares.iter().skip(threshold + 1))
{
    let big_w_i = PolynomialCommitment::eval_exponent_interpolation(
        threshold_plus1_identifiers,
        threshold_plus1_wshares,
        Some(identifier),
    )?;
    if big_w_i != *wshare {
        return Err(ProtocolError::AssertionFailed(
            "Exponent interpolation check failed.".to_string(),
        ));
    }
}
```

**Check 2 – Final integrity check (lines 303–311):** The protocol verifies `W = g^w`:

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

**Attack path:**

- A malicious participant `P_m` at index `≤ threshold` (in the interpolation basis) sends `W_m' = R^{a_m} · g^δ` for any `δ ≠ 0`. Because `W_m'` is part of the basis, it is **never checked by Check 1**. However, the interpolated `W` becomes `g^{k·a} · g^{δ·λ_m}` (where `λ_m` is the Lagrange coefficient for `P_m`), which is not equal to `g^w = g^{k·a}`. **Check 2 fails**, aborting the protocol.

- A malicious participant `P_m` at index `> threshold` (outside the basis) sends any wrong `W_m'`. **Check 1 fails** immediately, aborting the protocol.

In both cases the abort is indistinguishable from the honest parties' perspective — the error message is the generic `"Exponent interpolation check failed."` with no culprit identification. The presignature is permanently consumed.

The one-time-use constraint is explicitly documented:

> "Each presignature is consumed **exactly once** (one-time use)." [1](#0-0) 

The abort conditions are implemented at: [2](#0-1) 

The presigning entry point enforces `N = 2t+1` but provides no liveness guarantee against malicious `W_i` submissions: [3](#0-2) 

---

### Impact Explanation

**High — Permanent denial of signing for honest parties.**

Each presignature is one-time-use. When `do_presign` aborts, the presignature material is permanently lost. A malicious participant within the `t` threshold can deterministically abort every presigning attempt by sending `W_m' ≠ R^{a_m}`. Because the error message does not identify the culprit, honest parties cannot exclude the malicious participant without out-of-band coordination. The result is that signing becomes permanently unavailable for the honest party set, directly matching the "pools become unavailable" availability failure class from the external report. [4](#0-3) 

---

### Likelihood Explanation

**High.** The attack requires only that a malicious participant send any group element other than `R^{a_m}` as their `W_m`. This is a single-message deviation that is trivially executable by any participant who controls their own protocol implementation. No cryptographic break, no leaked secrets, and no external assumptions are required. The malicious participant can repeat the attack for every presigning session.

---

### Recommendation

Implement **identifiable abort** for the `W_i` verification step. After detecting that `W ≠ g^w`, each honest participant should individually verify `W_i =? R^{a_i}` for every received share. This requires participants to also commit to (or reveal) their `a_i` value so others can verify the individual `W_i = R^{a_i}` equation. The culprit can then be identified and excluded from future sessions, restoring liveness.

Additionally, document explicitly that the robust ECDSA presigning protocol does **not** provide liveness guarantees against malicious participants within the threshold, so that callers can implement appropriate retry and exclusion logic.

---

### Proof of Concept

1. Establish a presigning session with `N = 2t+1` participants, e.g., `t=2`, `N=5`.
2. Malicious participant `P_1` (index 0, in the interpolation basis) participates honestly through Rounds 1 and 2.
3. In Round 3, instead of broadcasting `W_1 = R^{a_1}`, `P_1` broadcasts `W_1' = R^{a_1} · G` (adds the generator point).
4. `W_1'` is accepted as part of the interpolation basis — Check 1 does not examine basis elements.
5. The interpolated `W = g^{k·a} · g^{λ_1}` ≠ `g^w = g^{k·a}`.
6. Check 2 (`W = g^w`) fails at line 303–311, returning `ProtocolError::AssertionFailed("Exponent interpolation check failed.")`.
7. All honest parties' presignature state is permanently destroyed.
8. `P_1` repeats steps 2–7 for every subsequent presigning attempt, permanently denying signing. [5](#0-4)

### Citations

**File:** src/ecdsa/robust_ecdsa/README.md (L12-12)
```markdown
Each presignature is consumed **exactly once** (one-time use).
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L74-83)
```rust
    // To prevent split-view attacks documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during presigning must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }

    let ctx = Comms::new();
    let fut = do_presign(ctx.shared_channel(), participants, me, args, rng);
    Ok(make_protocol(ctx, fut))
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L250-311)
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
