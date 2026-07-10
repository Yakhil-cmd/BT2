### Title
Presign Participant-Set Not Validated Against Triple-Generation Participant-Set, Causing Corrupt Presignatures - (File: src/ecdsa/ot_based_ecdsa/presign.rs)

---

### Summary

The OT-based ECDSA presign phase explicitly omits the check that the presigning participant set matches the participant set used during triple generation. Because `TriplePublicData` stores only the threshold and not the participant set, a malicious coordinator can invoke presigning with a different (but same-threshold) participant set than was used to generate the triples. This causes every participant to linearize their triple shares using wrong Lagrange coefficients, producing a cryptographically corrupt presignature that honest parties accept without error.

---

### Finding Description

**Root cause — explicit omission of participant-set validation:**

In `src/ecdsa/ot_based_ecdsa/presign.rs`, the public entry point `presign()` validates that the threshold of the supplied triples matches the presign threshold, but explicitly skips the analogous check for the participant set: [1](#0-0) 

```rust
// NOTE: We omit the check that the new participant set was present for
// the triple generation, because presumably they need to have been present
// in order to have shares.

// Also check that we have enough participants to reconstruct shares.
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(
        "New threshold must match the threshold of both triples".to_string(),
    ));
}
```

The word "presumably" is the vulnerability: it is an assumption, not an enforced invariant.

**Why the check cannot be performed — `TriplePublicData` stores no participant set:**

The `TriplePublicData` struct (referenced as `args.triple0.1` / `args.triple1.1`) exposes only `threshold`, `big_a`, `big_b`, and `big_c`. There is no stored record of which participants were present during triple generation, so the presign function has no data to compare against even if it wanted to.

**How the corruption propagates — wrong Lagrange coefficients:**

Inside `do_presign`, every participant linearizes their triple shares using Lagrange coefficients computed over the *presigning* participant set: [2](#0-1) 

```rust
let lambda_me = participants.lagrange::<Secp256>(me)?;

let k_prime_i = lambda_me * k_i;
let e_i: Scalar = lambda_me * e_i;

let a_prime_i = lambda_me * a_i;
let b_prime_i = lambda_me * b_i;

let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
let private_share = args.keygen_out.private_share.to_scalar();
let x_prime_i = lambda_me * private_share;
```

If the presigning participant set differs from the triple-generation participant set (even with the same threshold), `lambda_me` is computed over the wrong domain. The linearized shares `k'_i`, `a'_i`, `b'_i`, `x'_i` are all wrong. The resulting `PresignOutput` (`big_r`, `k`, `sigma`) is cryptographically inconsistent: the public nonce `big_r` will not correspond to the private nonce shares held by the signers.

**Protocol-level check that is bypassed:**

The orchestration documentation explicitly requires:

> P (keygen) ⊇ P₀ (triples) ⊇ P₁ (presigning) ⊇ P₂ (signing) [3](#0-2) 

This invariant is documented but never enforced in code at the presign boundary.

---

### Impact Explanation

**Impact: High — Corruption of presign outputs so honest parties accept inconsistent/unusable cryptographic outputs.**

Every honest participant runs `do_presign` to completion and returns `Ok(PresignOutput { … })` with no error. No participant detects that the Lagrange linearization was performed over the wrong set. The corrupt presignature is then passed to the signing phase, where the coordinator aggregates signature shares that were computed from mismatched nonce and sigma values. The final signature fails the `sig.verify()` check inside `do_sign_coordinator`: [4](#0-3) 

```rust
if !sig.verify(&public_key, &msg_hash) {
    return Err(ProtocolError::AssertionFailed(
        "signature failed to verify".to_string(),
    ));
}
```

At this point the presignature has already been consumed (it must never be reused per protocol rules), so the signing attempt is permanently lost. Repeated exploitation by a malicious coordinator exhausts the presignature pool and permanently denies signing to honest parties.

---

### Likelihood Explanation

The coordinator role is reachable by a malicious participant under the library's documented trust model. The coordinator controls which participant list is passed to each phase. Supplying a presigning participant list that differs from the triple-generation list by even one member (e.g., swapping one participant for another with the same threshold) silently triggers the bug. No cryptographic capability is required; only the ability to call `presign()` with a crafted `participants` slice and pre-existing triple shares.

---

### Recommendation

1. **Store the participant set inside `TriplePublicData`** (or a stable fingerprint of it, e.g., a hash of the sorted participant identifiers) at triple-generation time.
2. **Enforce the subset check in `presign()`**: verify that every member of the presigning participant list was present in the triple-generation participant set, and return `InitializationError::BadParameters` if not.
3. **Remove the "NOTE: We omit the check" comment** and replace it with the enforced check, eliminating the assumption that callers will always supply consistent participant sets.

---

### Proof of Concept

```
Setup:
  participants_triple = [A, B, C, D]   threshold = 2
  (triple0_pub, triple0_shares) = generate_triple(participants_triple, threshold)
  (triple1_pub, triple1_shares) = generate_triple(participants_triple, threshold)

Attack (malicious coordinator substitutes participant set):
  participants_presign = [A, B, C]     threshold = 2   ← D replaced by nothing; C added

  For each p in {A, B, C}:
    presign(
      participants = [A, B, C],        ← different from triple generation set
      me = p,
      args = PresignArguments {
        triple0: (triple0_shares[p], triple0_pub),   ← shares generated over {A,B,C,D}
        triple1: (triple1_shares[p], triple1_pub),
        threshold: 2,                  ← matches triple threshold → passes the only check
        keygen_out: …,
      }
    )

Result:
  presign() returns Ok(PresignOutput) for all three participants.
  lambda_me is computed over {A,B,C} instead of {A,B,C,D}.
  k'_i, a'_i, b'_i, sigma_i are all wrong.
  big_r is inconsistent with the private nonce shares.
  sign() → sig.verify() fails → ProtocolError.
  Presignature is consumed and cannot be reused.
  Signing is permanently denied for this presignature.
``` [5](#0-4) [2](#0-1) [3](#0-2)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L38-61)
```rust
    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

    // Also check that we have enough participants to reconstruct shares.
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(ctx.shared_channel(), participants, me, args);
    Ok(make_protocol(ctx, fut))
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L93-103)
```rust
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;

    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;
```

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L40-57)
```markdown
&\mathcal{P} &\supseteq &\mathcal{P}_0 &\supseteq &\mathcal{P}_1 &\supseteq &\mathcal{P}_2\cr
&N &\geq &N_0 &\geq &N_1 & \geq &N_2\cr
&t &&t_0 &&t_1 &&t_2\cr
\end{matrix}
$$

Each phase has a different set of parties, with each subsequent phase
having a subset of the parties present in the previous one.
The size of each party set, $N_i$, can also vary.
The thresholds can also change, subject to the following conditions:

$$
\begin{aligned}
&N_0 \geq t\cr
&N_1 \geq t_0 \geq t\cr
&N_2 \geq t_1 \geq t
\end{aligned}
$$
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L129-133)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```
