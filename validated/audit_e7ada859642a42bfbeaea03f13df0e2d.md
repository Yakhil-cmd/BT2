### Title
Missing Per-Share Validation of Signature Contributions Allows Malicious Participant to Permanently Deny Signing - (File: src/ecdsa/robust_ecdsa/sign.rs)

### Summary
In the Robust ECDSA signing protocol, the coordinator receives scalar signature shares `s_i` from each participant and sums them without validating each individual share against the participant's public presignature commitment. A single malicious participant can send an arbitrary scalar, causing the final signature verification to fail and permanently denying signing for all honest parties in that round.

### Finding Description
In `do_sign_coordinator` (`src/ecdsa/robust_ecdsa/sign.rs`, lines 127–166), the coordinator collects one `SerializableScalar` from each participant and accumulates them:

```rust
for (_, s_i) in
    recv_from_others::<SerializableScalar<C>>(&chan, wait_round, &participants, me).await?
{
    // Sum the linearized shares
    s += s_i.0;
}
```

The only post-collection checks are:
1. `s.is_zero()` on the **aggregate** (line 146)
2. `sig.verify(&public_key, &msg_hash)` on the **final signature** (line 159)

Neither check validates that any individual `s_i` is consistent with the corresponding participant's public presignature commitment (i.e., the `big_r`, `alpha`, `beta`, `c`, `e` values committed to during the presign phase). Because each participant's `s_i` is a deterministic function of their presignature share and the message hash, the coordinator has all the public information needed to verify each share independently before aggregating.

This is directly analogous to the Chainlink oracle bug: `answer != 0` and `answeredInRound >= roundId` are checked (some validation exists), but the critical recency check `block.timestamp - updateAt <= threshold` is absent. Here, the final signature is verified (some validation exists), but the critical per-share consistency check against the presignature commitment is absent.

The protocol enforces `participants.len() == 2 * max_malicious + 1` (line 86) and requires **all** participants to contribute valid shares. Without per-share validation, a single malicious participant can always inject an invalid `s_i`, causing `sig.verify` to fail at line 159 and returning `ProtocolError`, with no ability to identify the culprit.

### Impact Explanation
**High: Permanent denial of signing for honest parties under valid protocol inputs.**

Any single participant in the signing set can trivially abort every signing attempt they are included in by sending a random or zero scalar as their `s_i`. Because the protocol requires exactly `2 * max_malicious + 1` participants and all must contribute, and because there is no per-share accountability, the malicious participant cannot be identified or excluded. Honest parties cannot complete signing regardless of how many times they retry with the same participant set.

### Likelihood Explanation
**High.** The attacker is a protocol participant (a role reachable without privileged assumptions — any participant in the signing set qualifies). The attack requires sending a single malformed scalar in one protocol message. No cryptographic capability is needed. The attack succeeds deterministically on every invocation.

### Recommendation
Before summing shares, validate each received `s_i` against the corresponding participant's public presignature commitment. Specifically, for each participant `j` with presignature public values `(big_r_j, ...)`, verify that `s_i` satisfies the expected linear relation derivable from the committed presignature data and the public message hash. If any share fails validation, identify and exclude the malicious participant rather than aborting the entire protocol. This mirrors the Chainlink fix pattern: add the missing check (`block.timestamp - updateAt <= threshold`) so that a single bad value does not silently corrupt the aggregate result.

### Proof of Concept

1. Honest participants complete the presign phase, producing `RerandomizedPresignOutput` for each.
2. Signing is initiated with `max_malicious = 1`, requiring 3 participants.
3. Malicious participant `P_evil` receives the `wait_round` waitpoint and sends `s_evil = Scalar::ZERO` (or any random scalar) to the coordinator instead of the correct `s_me`.
4. The coordinator sums: `s = s_coordinator + s_honest + s_evil`. The result is incorrect.
5. `sig.verify(&public_key, &msg_hash)` at line 159 returns `false`.
6. The coordinator returns `ProtocolError::AssertionFailed("signature failed to verify")`.
7. Signing fails. `P_evil` repeats this for every signing attempt, permanently denying signing. No honest party can identify `P_evil` as the cause because no per-share check was performed. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/ecdsa/robust_ecdsa/sign.rs (L84-95)
```rust
    // The next two conditions prevent split-view attacks
    // documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during signing must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L138-143)
```rust
    for (_, s_i) in
        recv_from_others::<SerializableScalar<C>>(&chan, wait_round, &participants, me).await?
    {
        // Sum the linearized shares
        s += s_i.0;
    }
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L146-163)
```rust
    if s.is_zero().into() {
        return Err(ProtocolError::AssertionFailed(
            "signature part s cannot be zero".to_string(),
        ));
    }
    // Normalize s
    s.conditional_assign(&(-s), s.is_high());

    let sig = Signature {
        big_r: presignature.big_r,
        s,
    };

    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```
