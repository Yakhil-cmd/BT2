### Title
Presign `max_malicious` Not Validated Against DKG Threshold — (`src/ecdsa/robust_ecdsa/presign.rs`)

### Summary
The `PresignArguments` struct documents that `max_malicious` "must match the original threshold" from DKG, but this constraint is never enforced. Because `KeygenOutput` does not store the DKG threshold, the `presign()` function has no basis to validate the relationship. A malicious coordinator or misconfigured caller can supply a `max_malicious` that is inconsistent with the key shares, causing the presign protocol to generate polynomial shares of the wrong degree relative to the key-sharing polynomial, corrupting the presign output and making subsequent signing fail or produce cryptographically invalid results.

### Finding Description

In `src/ecdsa/robust_ecdsa/mod.rs`, the `PresignArguments` struct is defined as:

```rust
pub struct PresignArguments {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub max_malicious: MaxMalicious,
}
``` [1](#0-0) 

The comment explicitly states `max_malicious` "must match the original threshold," but `KeygenOutput` stores only `private_share: SigningShare` and `public_key: VerifyingKey` — it carries no record of the DKG threshold. [2](#0-1) 

The `presign()` validation checks only:
1. `participants.len() >= 2`
2. `max_malicious <= participants.len()`
3. `participants.len() == 2 * max_malicious + 1` [3](#0-2) 

There is no check that `max_malicious` equals `t_dkg − 1` (where `t_dkg` is the `ReconstructionLowerBound` used during DKG). Inside `do_presign`, the protocol generates polynomials whose degree is derived entirely from `max_malicious`:

```rust
let threshold = args.max_malicious.value();
let degree = threshold.checked_mul(2)...;
let polynomials = [
    Polynomial::generate_polynomial(None, threshold, rng)?, // fk
    Polynomial::generate_polynomial(None, threshold, rng)?, // fa
    zero_secret_polynomial(degree, rng)?,                   // fb
    zero_secret_polynomial(degree, rng)?,                   // fd
    zero_secret_polynomial(degree, rng)?,                   // fe
];
``` [4](#0-3) 

The key share `x_me` from DKG is then used directly as a scalar in:

```rust
let beta_me = c_me * x_me;
``` [5](#0-4) 

`c_me` is a share of a polynomial of degree `max_malicious`, while `x_me` is a share of a polynomial of degree `t_dkg − 1`. Their product `beta_me` lies on a polynomial of degree `max_malicious + (t_dkg − 1)`. If `max_malicious ≠ t_dkg − 1`, the degree of this product polynomial is wrong, and the signing-phase interpolation will either fail or produce an incorrect scalar, corrupting the final signature.

The DKG threshold validation in `assert_key_invariants` enforces `threshold >= 2` and `threshold <= participants.len()`, but the threshold value is never propagated into `KeygenOutput`: [6](#0-5) 

### Impact Explanation

**High — Corruption of presign outputs so honest parties accept unusable cryptographic outputs.**

When `max_malicious` is set to any value other than `t_dkg − 1`, the presign protocol completes without error (all polynomial-degree checks inside `do_presign` are self-consistent with the supplied `max_malicious`), but the resulting `PresignOutput` is cryptographically inconsistent with the key shares. The signing phase will then interpolate `beta` shares that lie on a polynomial of the wrong degree, producing an incorrect or unverifiable ECDSA signature. Honest parties who accepted the presign output will be unable to complete a valid signing operation, constituting a permanent denial of signing under valid protocol inputs.

### Likelihood Explanation

**Medium.** The `presign()` public API accepts `PresignArguments` directly from the caller. Any coordinator that assembles `PresignArguments` — whether maliciously or through misconfiguration — can supply a `max_malicious` that does not match the DKG threshold. Because `KeygenOutput` carries no threshold field, neither the library nor the caller has a programmatic way to detect the mismatch before the protocol runs. The comment in `PresignArguments` acknowledges the requirement but provides no enforcement, making accidental misconfiguration likely in practice.

### Recommendation

1. Add a `threshold: ReconstructionLowerBound` field to `KeygenOutput` (or a dedicated wrapper type for robust ECDSA) so the DKG threshold is carried forward.
2. In `presign()`, assert that `args.max_malicious.value() + 1 == args.keygen_out.threshold.value()` and return `InitializationError::BadParameters` if the invariant is violated.
3. Update the doc-comment on `PresignArguments::max_malicious` to reference the enforced relationship rather than leaving it as an unenforced note.

### Proof of Concept

```
1. Run DKG with 5 parties and ReconstructionLowerBound = 3 (t_dkg = 3).
   Each party's key share x_me lies on a degree-2 polynomial.

2. Assemble PresignArguments with:
     keygen_out  = <output from step 1>
     max_malicious = MaxMalicious(1)   // should be 2 for a 5-party, t=3 scheme

3. Call presign() with 3 participants (2*1+1 = 3 satisfies the N == 2t+1 check).
   presign() returns Ok — all internal checks pass.

4. do_presign generates:
     fk, fa of degree 1  (should be degree 2)
     fb, fd, fe of degree 2  (should be degree 4)
   beta_me = c_me * x_me  where c_me is on a degree-1 poly, x_me on a degree-2 poly
   => beta_me lies on a degree-3 polynomial.

5. In the signing phase, interpolating beta shares from 3 parties over a degree-3
   polynomial is underdetermined (need 4 points). The interpolated w is incorrect,
   producing a signature (r, s) that fails ECDSA verification.

Result: honest parties accepted a PresignOutput that cannot produce a valid signature,
permanently denying signing for this presignature batch.
```

### Citations

**File:** src/ecdsa/robust_ecdsa/mod.rs (L14-21)
```rust
/// The necessary inputs for the creation of a presignature.
pub struct PresignArguments {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type `KeygenOutput<Secp256K1Sha256>` from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub max_malicious: MaxMalicious,
}
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L30-83)
```rust
pub fn presign(
    participants: &[Participant],
    me: Participant,
    args: PresignArguments,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    if args.max_malicious.value() > participants.len() {
        return Err(InitializationError::BadParameters(
            "max_malicious must be less than or equals to participant count".to_string(),
        ));
    }

    let robust_ecdsa_threshold = args
        .max_malicious
        .value()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            InitializationError::BadParameters(
                "2*max_malicious+1 must be less than usize::MAX".to_string(),
            )
        })?;
    if robust_ecdsa_threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "2*max_malicious+1 must be less than or equals to participant count".to_string(),
        ));
    }

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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L97-112)
```rust
    let threshold = args.max_malicious.value();
    // Round 1
    let degree = threshold
        .checked_mul(2)
        .ok_or(ProtocolError::IntegerOverflow)?;
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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L322-324)
```rust
    let x_me = args.keygen_out.private_share.to_scalar();
    let beta_me = c_me * x_me;

```

**File:** src/dkg.rs (L558-596)
```rust
pub fn assert_key_invariants(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<ParticipantList, InitializationError> {
    let threshold = usize::from(threshold.into());
    // need enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // Step 1.1
    // validate threshold
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }

    // ensure uniqueness of participants in the participant list
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
    Ok(participants)
}
```
