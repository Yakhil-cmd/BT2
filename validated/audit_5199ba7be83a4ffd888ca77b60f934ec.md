### Title
Missing Participant-Set Validation Against `TriplePub.participants` in OT-Based ECDSA Presigning Allows Mismatched Triple Reuse - (File: src/ecdsa/ot_based_ecdsa/presign.rs)

---

### Summary

The `presign()` function in `src/ecdsa/ot_based_ecdsa/presign.rs` explicitly omits the check that the presigning participant set matches the participant set recorded in `TriplePub.participants`. The `TriplePub` struct stores the exact participant set that generated each triple, but this field is never cross-validated against the caller-supplied presigning participant set. A malicious coordinator or library caller can invoke `presign()` with a participant set that diverges from the one used during triple generation, causing the Lagrange linearization to operate over the wrong basis and corrupting the presign output for all honest parties.

---

### Finding Description

`TriplePub` explicitly records the participant set that generated the triple:

```rust
pub struct TriplePub {
    pub big_a: AffinePoint,
    pub big_b: AffinePoint,
    pub big_c: AffinePoint,
    /// The participants in generating this triple.
    pub participants: Vec<Participant>,
    /// The threshold which will be able to reconstruct it.
    pub threshold: ReconstructionLowerBound,
}
``` [1](#0-0) 

The `presign()` entry-point validates the threshold against `TriplePub.threshold` but contains an explicit comment acknowledging that the participant-set check is omitted:

```rust
// NOTE: We omit the check that the new participant set was present for
// the triple generation, because presumably they need to have been present
// in order to have shares.

// Also check that we have enough participants to reconstruct shares.
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(...));
}
``` [2](#0-1) 

The justification ("presumably they need to have been present in order to have shares") is not enforced by any cryptographic or structural check. The `TriplePub.participants` field is never read inside `presign()` or `do_presign()`.

Inside `do_presign()`, Lagrange coefficients are computed over the caller-supplied presigning participant set, not over `TriplePub.participants`:

```rust
let lambda_me = participants.lagrange::<Secp256>(me)?;
let k_prime_i = lambda_me * k_i;
let e_i: Scalar = lambda_me * e_i;
let a_prime_i = lambda_me * a_i;
let b_prime_i = lambda_me * b_i;
let x_prime_i = lambda_me * private_share;
``` [3](#0-2) 

The triple shares `(a_i, b_i, c_i)` are threshold-shared over the triple generation participant set. When the presigning participant set differs, the Lagrange basis is wrong, so the linearized shares are incorrect. The subsequent consistency checks:

```rust
if big_e != (ProjectivePoint::GENERATOR * e).to_affine() { ... }
if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
    || (ProjectivePoint::GENERATOR * beta != big_x + big_b) { ... }
``` [4](#0-3) 

will fail because the public commitments in `TriplePub` (`big_a`, `big_b`, `big_c`, `big_e`) were computed over the original triple generation participant set's Lagrange basis, not the mismatched presigning basis.

The orchestration specification explicitly requires the presigning participant set to be a subset of the triple generation participant set:

```
P ⊇ P0 ⊇ P1 ⊇ P2
``` [5](#0-4) 

This invariant is documented but not enforced in code.

---

### Impact Explanation

**Impact: High — Corruption of presign outputs causing honest parties to receive unusable cryptographic outputs / denial of signing.**

A malicious coordinator or library caller passes a `participants` slice to `presign()` that does not match `TriplePub.participants` for either or both triples. Because `TriplePub.participants` is never validated, `presign()` accepts the call. Inside `do_presign()`, every participant computes Lagrange coefficients over the wrong participant set, producing incorrect linearized shares. The public-commitment consistency checks then fail with `ProtocolError::AssertionFailed`, and all honest parties abort without producing a presignature. The attack can be repeated for every presigning attempt as long as the attacker controls the participant list or triple assignment, constituting a sustained denial of signing. Additionally, if a participant not present during triple generation is included in the presigning set, they have no valid triple share and must fabricate one; their fabricated contribution corrupts the shared sums, again causing all honest parties to abort.

---

### Likelihood Explanation

**Likelihood: Medium.**

The `participants` argument to `presign()` is a plain caller-supplied slice with no binding to the triples' provenance. Any library caller, coordinator, or participant who controls the presigning invocation can supply a mismatched participant set. The `TriplePub.participants` field is public and readable, so the mismatch is trivially constructable. No cryptographic capability or key material is required — only the ability to call `presign()` with attacker-chosen arguments, which is the normal library usage pattern.

---

### Recommendation

Inside `presign()`, after constructing the `ParticipantList`, validate that the presigning participant set is a subset of both `args.triple0.1.participants` and `args.triple1.1.participants`:

```rust
let triple0_participants = ParticipantList::new(&args.triple0.1.participants)
    .ok_or(InitializationError::DuplicateParticipants)?;
let triple1_participants = ParticipantList::new(&args.triple1.1.participants)
    .ok_or(InitializationError::DuplicateParticipants)?;

for p in participants.iter() {
    if !triple0_participants.contains(p) || !triple1_participants.contains(p) {
        return Err(InitializationError::BadParameters(
            "Presigning participant set must be a subset of triple generation participants".to_string()
        ));
    }
}
```

This enforces the invariant documented in the orchestration specification (`P0 ⊇ P1`) at the API boundary, eliminating the mismatch before any protocol messages are exchanged.

---

### Proof of Concept

1. Run triple generation with participant set `{P1, P2, P3}`, producing `(TripleShare_i, TriplePub)` for each `P_i`. `TriplePub.participants = [P1, P2, P3]`.
2. Call `presign(&[P1, P2, P4], P1, PresignArguments { triple0: (share_P1, triple_pub), triple1: ..., ... })` where `P4 ∉ {P1, P2, P3}`.
3. `presign()` accepts the call — no check against `triple_pub.participants` is performed. [6](#0-5) 
4. Inside `do_presign()`, `lambda_me` is computed over `{P1, P2, P4}` instead of `{P1, P2, P3}`, producing incorrect linearized shares.
5. `P4` has no valid triple share and sends a fabricated `e_i`.
6. The check `big_e != G * sum(e_i)` fails because `big_e` was committed over the `{P1, P2, P3}` basis. [4](#0-3) 
7. All honest parties (`P1`, `P2`) receive `ProtocolError::AssertionFailed` and abort. No presignature is produced.
8. The attacker repeats step 2 for every presigning attempt, permanently blocking signing for the honest parties.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/mod.rs (L56-65)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TriplePub {
    pub big_a: AffinePoint,
    pub big_b: AffinePoint,
    pub big_c: AffinePoint,
    /// The participants in generating this triple.
    pub participants: Vec<Participant>,
    /// The threshold which will be able to reconstruct it.
    pub threshold: ReconstructionLowerBound,
}
```

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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L127-131)
```rust
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }
```

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L31-47)
```markdown
Concretely, we have the following situation:

$$
\begin{matrix}
&\scriptsize{\text{Key-Gen}}
&&\scriptsize{\text{Triples}}
&&\scriptsize{\text{Presigning}}
&&\scriptsize{\text{Signing}}
\cr
&\mathcal{P} &\supseteq &\mathcal{P}_0 &\supseteq &\mathcal{P}_1 &\supseteq &\mathcal{P}_2\cr
&N &\geq &N_0 &\geq &N_1 & \geq &N_2\cr
&t &&t_0 &&t_1 &&t_2\cr
\end{matrix}
$$

Each phase has a different set of parties, with each subsequent phase
having a subset of the parties present in the previous one.
```
