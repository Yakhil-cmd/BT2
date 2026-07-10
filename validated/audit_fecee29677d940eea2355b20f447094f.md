### Title
Order-Dependent Interpolation Basis Selection in Robust ECDSA Presign Enables Unattributable Denial of Signing - (File: src/ecdsa/robust_ecdsa/presign.rs)

---

### Summary

In `do_presign`, the exponent-interpolation consistency check for `R_i` and `W_i` values is order-dependent: the first `t+1` participants by sorted participant ID are silently used as the interpolation basis and are **never cross-validated**, while only the last `t` participants are checked against that basis. A malicious participant whose ID places them in the first `t+1` sorted positions can submit a corrupted `R_i` that is invisible to the check, causing the check to fail for honest participants in the last `t` positions. Because the error is attributed to the wrong parties, the malicious participant cannot be identified or excluded, enabling persistent denial of signing.

---

### Finding Description

`ParticipantList::new` sorts participants by their `u32` ID and `ParticipantMap::into_vec_or_none` returns data in that fixed sorted order. [1](#0-0) 

In `do_presign`, after collecting all `(R_i, w_i)` pairs into `ParticipantMap` structures, the code converts them to sorted vectors and then **splits at position `threshold + 1`** to select the interpolation basis: [2](#0-1) 

The first `t+1` elements (lowest participant IDs) become `threshold_plus1_verifying_shares` — the interpolation basis. The check then iterates only over the **remaining `t` elements** (highest participant IDs): [3](#0-2) 

The identical order-dependent split is repeated for the `W_i` shares in the second interpolation check: [4](#0-3) 

The final `big_r` is then computed exclusively from the first `t+1` basis elements: [5](#0-4) 

Participants in the first `t+1` sorted positions are **never checked against an independent interpolation**. Their submitted values are unconditionally trusted as the polynomial basis.

---

### Impact Explanation

A malicious participant whose `u32` ID places them among the first `t+1` sorted participants submits a corrupted `R_i = g^{k'_i}` where `k'_i ≠ k_i`. Because this participant is in the basis, no check validates their value against the true polynomial. The corrupted basis polynomial differs from the true degree-`t` polynomial. When the check evaluates the last `t` honest participants' `R_j` values against this wrong basis, the interpolated values do not match, and the protocol aborts with `"Exponent interpolation check failed."` — an error that names no participant.

The honest participants in the last `t` positions appear to be the source of the failure. The actual malicious participant in the basis is invisible to the check. Since no participant can be identified and excluded, the malicious party can repeat this attack on every presign attempt, causing **permanent denial of signing** for all honest parties.

This is categorically different from a malicious participant in the last `t` positions: there, the check directly catches the inconsistent value (the check iterates over their position), making correct blame attribution possible and allowing the protocol to be retried without them.

---

### Likelihood Explanation

The attack requires only that the malicious participant's `u32` ID is numerically among the lowest `t+1` in the signing group. Participant IDs are assigned externally by the application and are not secret. An adversary who can influence ID assignment, or who simply registers with a low numeric ID, reliably occupies a basis position. With `t=2` (the minimum meaningful threshold, `2t+1=5` participants), any participant with one of the three lowest IDs qualifies. The attack requires no cryptographic break, no leaked keys, and no coordination beyond sending a single wrong group element in Round 2.

---

### Recommendation

Replace the positional `split_at_checked(threshold + 1)` basis selection with a symmetric check that validates **every** participant's `R_i` against the interpolation of all others, or use a commitment-based approach where each participant commits to their `R_i` before revealing it, allowing the interpolation to be verified against all `2t+1` points simultaneously without privileging any positional subset. The check should be independent of participant ID ordering so that no participant occupies an unchecked "basis" role by virtue of their numeric ID.

---

### Proof of Concept

Setup: `t = 2`, participants `P1 < P2 < P3 < P4 < P5` (sorted by ID). Basis positions: `P1, P2, P3` (first `t+1 = 3`). Checked positions: `P4, P5` (last `t = 2`).

1. Malicious participant `P1` participates honestly in Round 1 (sends correct polynomial evaluations).
2. In Round 2, `P1` waits to receive `R_4` and `R_5` from `P4` and `P5`.
3. `P1` sends a corrupted `R'_1 = g^{k'_1}` where `k'_1 ≠ k_1`.
4. The basis polynomial is now determined by `(R'_1, R_2, R_3)` — a wrong degree-`t` polynomial.
5. The check at lines 194–213 evaluates this wrong polynomial at `P4` and `P5`'s identifiers. Since `P4` and `P5` are honest, their `R_4, R_5` lie on the **true** polynomial, not the corrupted one. The check fails.
6. `do_presign` returns `ProtocolError::AssertionFailed("Exponent interpolation check failed.")` with no participant identified.
7. `P1` repeats this on every presign invocation. Signing is permanently denied. `P1` is never excluded. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** src/participants.rs (L86-104)
```rust
impl ParticipantList {
    // For optimization reasons, another method needs this.
    fn new_vec(mut participants: Vec<Participant>) -> Option<Self> {
        participants.sort();

        let indices: HashMap<_, _> = participants
            .iter()
            .enumerate()
            .map(|(p, x)| (*x, p))
            .collect();

        if indices.len() < participants.len() {
            return None;
        }

        Some(Self {
            participants,
            indices,
        })
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L162-175)
```rust
    while !signingshares_map.full() {
        // Step 3.1
        let (from, (big_r_p, w_p)): (_, (_, SigningShare<C>)) = chan.recv(wait_round_2).await?;
        // collect big_r_p and w_p in maps that will be later ordered
        // if the sender has already sent elements then put will return immediately
        signingshares_map.put(from, SerializableScalar(w_p.to_scalar()));
        verifyingshares_map.put(from, big_r_p);
    }

    let identifiers: Vec<Scalar> = signingshares_map
        .participants()
        .iter()
        .map(Participant::scalar::<C>)
        .collect();
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L186-213)
```rust
    let (threshold_plus1_identifiers, _) = identifiers
        .split_at_checked(threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough identifiers".to_string()))?;
    let (threshold_plus1_verifying_shares, _) = verifying_shares
        .split_at_checked(threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough verifying shares".to_string()))?;

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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L218-222)
```rust
    let big_r = PolynomialCommitment::eval_exponent_interpolation(
        threshold_plus1_identifiers,
        threshold_plus1_verifying_shares,
        None,
    )?;
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L270-291)
```rust
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
```
