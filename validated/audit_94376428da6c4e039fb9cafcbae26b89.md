### Title
Missing Participant-Set Validation in `presign()` Allows Coordinator to Corrupt Presignature Outputs Using Mismatched Triples - (File: `src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

The `presign()` function in the OT-based ECDSA module explicitly omits the check that the participant set used for presigning matches the participant set that was present during Beaver triple generation. A malicious coordinator can initiate a presign session with a participant set that differs from the one used to generate the triples, causing honest participants to compute and accept cryptographically corrupted presignature outputs.

---

### Finding Description

In `src/ecdsa/ot_based_ecdsa/presign.rs`, the public entry point `presign()` validates threshold consistency between the triples and the new session, but explicitly skips the participant-set membership check: [1](#0-0) 

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

The code checks that the **threshold** of the triples matches the presign threshold, but there is **no check** that the **participant identifiers** in the triples match the participant identifiers in the presign session.

Beaver triples are generated with participant-specific polynomial evaluations. In `do_presign()`, the Lagrange coefficient `lambda_me` is computed over the **presign** participant list: [2](#0-1) 

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

The triple shares `k_i`, `e_i`, `a_i`, `b_i`, `c_i` were evaluated at participant identifiers from the **triple generation** session. If the presign session uses a different participant set (even with the same threshold), the Lagrange re-linearization is applied with wrong coefficients relative to the triple's polynomial basis. The public consistency checks that follow (e.g., `big_e != (ProjectivePoint::GENERATOR * e).to_affine()` and `alpha*G =?= K + A`) verify algebraic relationships **within** the presign session, but cannot detect that the underlying triple shares were produced for a different participant set. [3](#0-2) 

---

### Impact Explanation

When a malicious coordinator initiates a presign session with a participant set `P'` that differs from the set `P` used during triple generation, the Lagrange linearization of triple shares is computed with wrong basis polynomials. This produces a `PresignOutput` whose internal values (`big_r`, `k`, `chi`, etc.) are algebraically inconsistent with the actual secret key shares. Honest participants complete the protocol and store this corrupted presignature. When the corrupted presignature is later used in `sign()`, the resulting signature will fail to verify against the public key, or the coordinator's final verification step will abort. In either case, honest parties have accepted and stored an unusable, inconsistent presignature output.

**Mapped impact**: High — Corruption of presign outputs so honest parties accept inconsistent or unusable cryptographic outputs.

---

### Likelihood Explanation

The coordinator is a semi-trusted role that controls which participants are included in each protocol session. A malicious coordinator (or a coordinator operating under a split-view attack) can trivially supply a participant list `P'` that differs from the triple generation set `P` while keeping the threshold identical (satisfying the only check that exists). No cryptographic capability is required — only the ability to call `presign()` with attacker-chosen `participants` and `args`.

---

### Recommendation

Before entering `do_presign()`, validate that the participant set used for presigning is identical to the participant set recorded in the triple metadata. Concretely, `PresignArguments` should carry the participant set from triple generation (or a commitment to it), and `presign()` should assert:

```rust
// Pseudocode
assert!(triple0_participants == presign_participants,
    "Participant set mismatch between triple generation and presign");
assert!(triple1_participants == presign_participants,
    "Participant set mismatch between triple generation and presign");
```

This mirrors the fix recommended in the original report: verify that the prerequisite protocol phase (triple generation) was completed by the same set of participants before proceeding with the dependent phase (presigning).

---

### Proof of Concept

1. Participants `{A, B, C}` (threshold 2) run triple generation and each obtains triple shares evaluated at identifiers `{id_A, id_B, id_C}`.
2. A malicious coordinator initiates `presign()` with participant set `{A, B, D}` (same threshold 2, but `D` replaces `C`).
3. The only guard — threshold equality — passes because both sets have threshold 2.
4. Inside `do_presign()`, `lambda_me` is computed over `{A, B, D}`. Participant `A`'s triple share `k_i` was evaluated at `id_A` under the polynomial basis for `{A, B, C}`, but is now re-linearized with the Lagrange coefficient for `id_A` in `{A, B, D}` — a different value.
5. The public-key consistency checks (`big_e == e*G`, `alpha*G == K + A`) operate on the re-linearized values and may pass (since each participant's local computation is internally consistent), but the aggregate `PresignOutput` is cryptographically inconsistent with the actual secret key.
6. All honest participants store the corrupted `PresignOutput`. Any subsequent `sign()` call using this presignature produces a signature that fails verification, permanently wasting the presignature material and denying the signing operation. [4](#0-3)

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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L92-103)
```rust
    // Spec 1.1
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;

    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L125-131)
```rust
    // E =?= e*G
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }
```
