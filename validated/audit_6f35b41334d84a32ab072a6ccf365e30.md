### Title
Duplicate Beaver Triple in `PresignArguments` Enables Private Key Extraction — (`src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

The `presign()` function in `src/ecdsa/ot_based_ecdsa/presign.rs` accepts a `PresignArguments` struct containing two Beaver triples (`triple0`, `triple1`). There is no check that these two triples are distinct. If the same triple is supplied for both slots — by a malicious or buggy orchestrator — the presign protocol broadcasts enough information to reconstruct the aggregate secret `k`, and a subsequent signing round then directly exposes the private signing key `x`.

---

### Finding Description

`PresignArguments` is a plain public struct with two public fields:

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs  lines 24-34
pub struct PresignArguments {
    pub triple0: (TripleShare, TriplePub),
    pub triple1: (TripleShare, TriplePub),
    pub keygen_out: KeygenOutput,
    pub threshold: ReconstructionLowerBound,
}
```

The `presign()` entry-point validates participant uniqueness, threshold bounds, and that the threshold matches both triples' metadata, but **never checks that `triple0` and `triple1` are distinct**:

```rust
// src/ecdsa/ot_based_ecdsa/presign.rs  lines 43-50
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(...));
}
let participants =
    ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;
``` [1](#0-0) 

Inside `do_presign`, the two triples are consumed as follows:

```
k_i  = triple0.0.a      (line 83)
e_i  = triple0.0.c      (line 84)
a_i  = triple1.0.a      (line 72)
b_i  = triple1.0.b      (line 73)
c_i  = triple1.0.c      (line 74)
``` [2](#0-1) 

When `triple0 == triple1`, every participant has `k_i = a_i`. The masking values that are broadcast in Round 2 become:

```
alpha_i = lambda_i * k_i + lambda_i * a_i  =  2 * lambda_i * k_i
beta_i  = lambda_i * x_i + lambda_i * b_i
``` [3](#0-2) 

Aggregating across all parties:

```
alpha = Σ alpha_j = 2k          ← k is the reconstructed nonce secret
beta  = x + b
```

Because `alpha = 2k` is broadcast to every participant, any observer immediately computes `k = alpha / 2`. The existing consistency checks still pass because `big_k = big_a` and `big_e = big_c` when the same `TriplePub` is used for both slots:

```rust
// line 162-163
if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)   // 2k·G == 2·big_k ✓
    || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
``` [4](#0-3) 

The aggregate sigma value (reconstructed from the shares) simplifies to:

```
sigma = alpha·x − beta·a + c
      = (k+a)·x − (x+b)·a + c
      = kx − ab + c
      = kx                      (since c = a·b = k·b, so −ab+c = 0)
``` [5](#0-4) 

In the subsequent signing round the coordinator produces the aggregate ECDSA signature:

```
s = k · (H(m) + r · x)
```

Since `k = alpha/2` is already known, the private key is directly recoverable:

```
x = (s/k − H(m)) / r
```

`TriplePub` derives `PartialEq` + `Eq`, so a simple equality check on the public parts would be sufficient to detect the duplicate at initialization time. [6](#0-5) 

---

### Impact Explanation

**Critical — Extraction of the private signing key.**

An attacker who controls the orchestration layer (or a buggy caller) supplies the same `TripleGenerationOutput` for both `triple0` and `triple1` in `PresignArguments`. The presign protocol completes without error, broadcasting `alpha = 2k`. Combined with the signature produced in the signing round, the full private key `x` is computable by any party that observed the presign transcript. This matches the allowed Critical impact: *"Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets."*

---

### Likelihood Explanation

The `PresignArguments` struct is a plain public struct with no invariant enforcement. The orchestrator is responsible for distributing two independently generated triples per presignature. A malicious orchestrator can trivially pass the same triple twice. A buggy orchestrator (e.g., accidentally reusing a `TripleGenerationOutput` from a `HashMap` lookup with the same key) would trigger the same outcome. The `presign()` API provides no guard against this, and the protocol's own consistency checks do not catch it because the degenerate case is algebraically self-consistent. [7](#0-6) 

---

### Recommendation

Add a distinctness check on the public triple commitments inside `presign()` before constructing the protocol:

```rust
// in presign(), after threshold checks and before ParticipantList::new
if args.triple0.1 == args.triple1.1 {
    return Err(InitializationError::BadParameters(
        "triple0 and triple1 must be distinct".to_string(),
    ));
}
```

`TriplePub` already derives `PartialEq` + `Eq`, so this check is zero-cost and requires no new infrastructure. [8](#0-7) 

---

### Proof of Concept

1. Run DKG to obtain `keygen_out` for all participants.
2. Generate a single triple `t = generate_triple(participants, me, threshold, rng)`.
3. Construct `PresignArguments { triple0: t.clone(), triple1: t.clone(), keygen_out, threshold }` for every participant.
4. Run the presign protocol. It completes successfully; the broadcast `alpha` satisfies `alpha = 2k`.
5. Compute `k = alpha / 2` from the observed transcript.
6. Run the signing protocol on any message `m` to obtain signature `(r, s)`.
7. Compute `x = (s * k⁻¹ − H(m)) * r⁻¹` to recover the private key.
8. Verify: `x · G == public_key`. [9](#0-8)

### Citations

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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L64-186)
```rust
async fn do_presign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    args: PresignArguments,
) -> Result<PresignOutput, ProtocolError> {
    // Round 1
    // Extracting triples private variables (ai, bi, ci)
    let a_i = args.triple1.0.a;
    let b_i = args.triple1.0.b;
    let c_i = args.triple1.0.c;

    // Extracting triples public variables (A, B, _)
    // notice C is not used
    let big_a: ProjectivePoint = args.triple1.1.big_a.into();
    let big_b: ProjectivePoint = args.triple1.1.big_b.into();

    // Extracting triples private variables (ki, _, ei)
    // notice di is not used
    let k_i = args.triple0.0.a;
    let e_i = args.triple0.0.c;

    // Extracting triples public variables (K, D, E)
    let big_k: ProjectivePoint = args.triple0.1.big_a.into();
    let big_d = args.triple0.1.big_b;
    let big_e = args.triple0.1.big_c;

    // linearize ki ei ai bi ci xi
    // Spec 1.1
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;

    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;

    // Send ei
    // Spec 1.2
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &e_i)?;

    // Receive ej and compute e = SUM_j ej
    // Spec 1.3
    let mut e = e_i;

    for (_, e_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
        if e_j.is_zero().into() {
            return Err(ProtocolError::AssertionFailed(
                "Received zero share of kd, indicating a triple wasn't available.".to_string(),
            ));
        }

        // Spec 1.4
        e += e_j;
    }

    // E =?= e*G
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }

    // Round 2
    // alphai = ki' + ai'
    // Spec 2.1
    let alpha_i: Scalar = k_prime_i + a_prime_i;
    // betai = xi' + bi'
    let beta_i: Scalar = x_prime_i + b_prime_i;

    // Send alphai and betai
    // Spec 2.2
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &(alpha_i, beta_i))?;

    // Receive and compute alpha = SUM_j alphaj
    // Receive and compute beta = SUM_j betaj
    // Spec 2.3
    let mut alpha = alpha_i;
    let mut beta = beta_i;

    for (_, (alpha_j, beta_j)) in
        recv_from_others::<(Scalar, Scalar)>(&chan, wait1, &participants, me).await?
    {
        // Spec 2.4
        alpha += alpha_j;
        beta += beta_j;
    }

    // alpha*G =?= K + A
    // beta*G =?= X + B
    // Spec 2.5
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }

    // Compute R = 1/e * D
    // Spec 2.6
    let e_inv: Option<Scalar> = e.invert().into();
    let e_inv =
        e_inv.ok_or_else(|| ProtocolError::AssertionFailed("failed to invert kd".to_string()))?;
    let big_r = (big_d * e_inv).into();

    // sigmai = alpha*xi - beta*ai + ci
    // Spec 2.7
    let sigma_i = alpha * private_share - (beta * a_i - c_i);

    Ok(PresignOutput {
        big_r,
        k: k_i,
        sigma: sigma_i,
    })
}
```

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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L24-34)
```rust
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
