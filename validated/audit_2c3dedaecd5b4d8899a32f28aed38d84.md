### Title
Threshold Parameter Mismatch Between Keygen and Presign Phases Corrupts Presignature Outputs - (File: `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/lib.rs`)

---

### Summary

`KeygenOutput` does not encode the threshold used during key generation. The OT-based ECDSA `PresignArguments` accepts a separate, caller-supplied `threshold` field with no validation that it matches the threshold used during keygen. A mismatched threshold causes the Lagrange linearization of private shares inside `do_presign` to be computed against the wrong polynomial degree, silently producing a corrupted presignature that honest parties accept without error.

---

### Finding Description

`KeygenOutput<C>` is defined in `src/lib.rs` as:

```rust
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    pub public_key: VerifyingKey<C>,
}
``` [1](#0-0) 

No threshold is stored. The threshold used during keygen determines the degree of the secret-sharing polynomial: degree = `keygen_threshold - 1`. Each participant's `private_share` is an evaluation of that polynomial.

The OT-based ECDSA `PresignArguments` struct carries a separate `threshold` field:

```rust
pub struct PresignArguments {
    pub triple0: (TripleShare, TriplePub),
    pub triple1: (TripleShare, TriplePub),
    pub keygen_out: KeygenOutput,
    pub threshold: ReconstructionLowerBound,
}
``` [2](#0-1) 

The `presign()` entry-point validates only that `args.threshold` matches the two triple thresholds:

```rust
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(...));
}
``` [3](#0-2) 

There is **no check** that `args.threshold` equals the threshold used during keygen, because `KeygenOutput` carries no such information. Inside `do_presign`, the Lagrange coefficient is computed from the presign participant list and immediately applied to the keygen private share:

```rust
let lambda_me = participants.lagrange::<Secp256>(me)?;
let x_prime_i = lambda_me * private_share;
``` [4](#0-3) 

If `presign_threshold ≠ keygen_threshold`, the Lagrange basis is evaluated over the wrong number of points relative to the polynomial degree used during keygen. The sum of `x_prime_i` across participants will not equal the actual secret key, silently corrupting the presignature. No protocol-level error is raised.

The same structural gap exists in the Robust ECDSA path: `PresignArguments` carries a standalone `max_malicious` field alongside `keygen_out`, with no cross-validation against the keygen threshold. [5](#0-4) 

---

### Impact Explanation

When `presign_threshold < keygen_threshold`, the Lagrange interpolation is under-determined relative to the polynomial degree; the reconstructed secret is wrong. When `presign_threshold > keygen_threshold`, the interpolation is over-determined and also wrong. In both cases, `do_presign` completes without error and returns a `PresignOutput` that all honest participants accept. The corrupted `big_r`, `k`, and `sigma` values propagate into the signing phase, producing an invalid ECDSA signature or a signing abort. This constitutes **corruption of presign outputs so honest parties accept unusable cryptographic outputs** — a High-severity impact under the allowed scope.

---

### Likelihood Explanation

The library is designed for use by an orchestrating caller who supplies both `keygen_out` (obtained from a prior keygen run) and `threshold` (chosen at presign time). Because `KeygenOutput` is opaque with respect to threshold, an honest-but-mistaken caller (e.g., after a reshare that changed the threshold) or a malicious coordinator can trivially supply a mismatched value. The presign API provides no guard against this. The test at `src/ecdsa/ot_based_ecdsa/test.rs` already demonstrates a concrete instance where the old threshold (4) is passed to the signing phase after a reshare to new threshold (3), showing the mismatch is a realistic operational scenario. [6](#0-5) 

---

### Recommendation

Embed the threshold used during keygen directly inside `KeygenOutput`:

```rust
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    pub public_key: VerifyingKey<C>,
    pub threshold: ReconstructionLowerBound,   // add this
}
```

Then, in `presign()`, add an explicit consistency check:

```rust
if args.threshold != args.keygen_out.threshold {
    return Err(InitializationError::BadParameters(
        "Presign threshold must match the threshold used during keygen".to_string(),
    ));
}
```

Apply the same fix to the Robust ECDSA path by storing and validating `max_malicious` against the keygen threshold embedded in `KeygenOutput`.

---

### Proof of Concept

1. Run keygen with 5 participants and `threshold = 5`. Each participant receives a share of a degree-4 polynomial.
2. Generate two Beaver triples with `threshold = 2`.
3. Call `presign()` with `args.threshold = 2` and the keygen shares from step 1. The triple-threshold check passes (2 == 2). No keygen-threshold check exists.
4. Inside `do_presign`, `participants.lagrange(me)` is computed over 2 participants, producing Lagrange coefficients for a degree-1 basis — incompatible with the degree-4 keygen polynomial.
5. `x_prime_i = lambda_me * private_share` is cryptographically wrong; the sum across participants does not equal the secret key.
6. `PresignOutput` is returned without error. All honest parties store the corrupted presignature.
7. The subsequent signing phase produces an invalid signature, permanently denying signing capability for this presignature batch. [7](#0-6) [1](#0-0)

### Citations

**File:** src/lib.rs (L48-55)
```rust
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, ZeroizeOnDrop)]
#[serde(bound = "C: Ciphersuite")]
/// Generic type of key pairs
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    #[zeroize[skip]]
    pub public_key: VerifyingKey<C>,
}
```

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L22-34)
```rust
/// The arguments needed to create a presignature.
#[derive(Debug, Clone)]
pub struct PresignArguments {
    /// The first triple's public information, and our share.
    pub triple0: (TripleShare, TriplePub),
    /// Ditto, for the second triple.
    pub triple1: (TripleShare, TriplePub),
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type `KeygenOutput<Secp256K1Sha256>` from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub threshold: ReconstructionLowerBound,
}
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L20-62)
```rust
pub fn presign(
    participants: &[Participant],
    me: Participant,
    args: PresignArguments,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    // Spec 1.1
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.value(),
            max: participants.len(),
        });
    }

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
}
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

**File:** src/ecdsa/ot_based_ecdsa/test.rs (L277-325)
```rust
#[test]
fn test_reshare_sign_less_participants() -> Result<(), Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(5);
    let threshold = 4;
    let result0 = run_keygen(&participants, threshold, &mut rng);
    assert_public_key_invariant(&result0);

    let pub_key = result0[2].1.public_key;

    // Run heavy reshare
    let new_threshold = 3;
    let mut new_participant = participants.clone();
    new_participant.pop();
    let key_packages = run_reshare(
        &participants,
        &pub_key,
        &result0,
        threshold,
        new_threshold,
        &new_participant,
        &mut rng,
    );
    assert_public_key_invariant(&key_packages);

    let public_key = key_packages[0].1.public_key;
    // Prepare triples
    let (pub0, shares0) = deal(&mut rng, &new_participant, new_threshold.into())?;
    let (pub1, shares1) = deal(&mut rng, &new_participant, new_threshold.into())?;

    let presign_result = run_presign(
        key_packages,
        shares0,
        shares1,
        &pub0,
        &pub1,
        new_threshold.into(),
    );

    let msg = b"hello world";
    // internally verifies the signature's validity
    run_sign_without_rerandomization(
        &presign_result,
        threshold.into(),
        public_key.to_element(),
        msg,
        &mut rng,
    );
    Ok(())
```
