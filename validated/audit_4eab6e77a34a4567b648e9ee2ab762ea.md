Now I have all the code I need. Let me trace the math precisely.

### Title
Identical Triple Inputs in `presign()` Leak Nonce `k` via Broadcast `alpha = 2k`, Enabling Full Private Key Recovery — (`src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

`presign()` only validates that `triple0` and `triple1` share the same threshold; it does not check that they are distinct triples. When a malicious coordinator supplies identical `(triple0, triple1)` to all parties, the Lagrange-scaled nonce share `k'_i` equals the blinding share `a'_i`, so each party broadcasts `alpha_i = 2*k'_i`. The aggregated `alpha = 2k` is visible to every participant. Because `k = alpha * 2^{-1} mod p` is now known, any party can recover the private key `x` from the first signature produced with this presignature.

---

### Finding Description

**Missing guard — lines 43–47:**

The only validation on the two triples is threshold equality:

```rust
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(...));
}
```

There is no check that `triple0.1.big_a != triple1.1.big_a` (or any other public-key field). A caller may pass the same `(TripleShare, TriplePub)` for both arguments. [1](#0-0) 

**Variable aliasing when `triple0 == triple1`:**

```
k_i  = triple0.0.a   (line 83)
a_i  = triple1.0.a   (line 72)
```

When the same triple is passed, `k_i == a_i`, `b_i == d_i`, `c_i == e_i`. [2](#0-1) 

**Lagrange scaling preserves the equality:**

```
k'_i = λ_i * k_i   (line 95)
a'_i = λ_i * a_i   (line 98)
```

Since `k_i == a_i`, we get `k'_i == a'_i`. [3](#0-2) 

**`alpha_i` becomes `2*k'_i`:**

```rust
let alpha_i: Scalar = k_prime_i + a_prime_i;  // = 2 * k'_i
``` [4](#0-3) 

**`alpha_i` is broadcast to every participant:**

```rust
chan.send_many(wait1, &(alpha_i, beta_i))?;
```

Every party receives all `alpha_j` values and reconstructs `alpha = Σ alpha_j = 2k`. [5](#0-4) 

**The consistency check at line 162 does NOT catch this:**

When `triple0 == triple1`, `big_k == big_a`, so the check becomes:
```
alpha*G  =?=  big_k + big_a
2k*G     =?=  2*big_k          ✓  (always true)
```

The protocol proceeds without aborting. [6](#0-5) 

**`sigma` still computes to `k*x` (protocol completes successfully):**

With `a_i = k_i`, `b_i = d_i`, `c_i = k_i*d_i`:

```
sigma_i = alpha * x_i - (beta * a_i - c_i)
        = 2k*x_i - ((x+d)*k_i - k_i*d_i)
        = 2k*x_i - x*k_i - d*k_i + k_i*d_i

sigma   = 2kx - kx - dk + kd = kx   ✓
```

The presignature is algebraically valid and produces a real signature — no party detects the attack. [7](#0-6) 

---

### Impact Explanation

Every participant computes `alpha = 2k` from the broadcast shares. From `k = alpha * 2^{-1} mod p` and any resulting ECDSA signature `(r, s)` over message hash `h`:

```
s = k^{-1} * (h + r*x)
x = (s*k - h) * r^{-1}   mod p
```

This is a complete, one-shot private key extraction. The `PresignOutput` struct confirms that `k` (the raw nonce share) is stored and later used in signing: [8](#0-7) 

**Impact: Critical — full private key extraction.**

---

### Likelihood Explanation

The `PresignArguments` struct is a plain public struct with no invariant enforcement: [9](#0-8) 

A malicious coordinator who controls triple distribution (a documented role in the Cait-Sith pipeline) can trivially pass the same `(TripleShare, TriplePub)` for both `triple0` and `triple1`. The scope rules explicitly include "malicious coordinator/participant action" as a valid entry point. No cryptographic assumption needs to be broken; the attack is a pure input-crafting exploit against a missing validation.

---

### Recommendation

Add a check in `presign()` that the two triples have distinct public nonce commitments before entering `do_presign`:

```rust
if args.triple0.1.big_a == args.triple1.1.big_a {
    return Err(InitializationError::BadParameters(
        "triple0 and triple1 must be independent (same big_a detected)".to_string(),
    ));
}
```

Checking `big_a` (the commitment to the `a` share) is sufficient because `k_i` and `a_i` are both drawn from the `.a` field of their respective triples, and equality of the public commitments implies equality of the underlying secrets with overwhelming probability. [1](#0-0) 

---

### Proof of Concept

```rust
// All parties receive the SAME triple for both triple0 and triple1.
// (Simulates a malicious coordinator.)
let (triple_pub, triple_shares) = deal(&mut rng, &participants, threshold).unwrap();

for (p, share) in participants.iter().zip(triple_shares.iter()) {
    let protocol = presign(
        &participants,
        *p,
        PresignArguments {
            triple0: (share.clone(), triple_pub.clone()),  // same triple
            triple1: (share.clone(), triple_pub.clone()),  // same triple
            keygen_out: keygen_outputs[p].clone(),
            threshold,
        },
    ).unwrap();
    // ...
}

// After protocol completes, every party has alpha = 2k.
// k = alpha * modular_inverse(2, p)
// From any signature (r, s) over hash h:
// x = (s * k - h) * modular_inverse(r, p)
```

The protocol completes without error, produces a structurally valid `PresignOutput`, and the resulting signature is usable — but `k` is fully exposed through the broadcast `alpha`, enabling immediate private key recovery.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L43-47)
```rust
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L72-89)
```rust
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
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L95-99)
```rust
    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L136-136)
```rust
    let alpha_i: Scalar = k_prime_i + a_prime_i;
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L143-157)
```rust
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
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L162-168)
```rust
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L177-185)
```rust
    // sigmai = alpha*xi - beta*ai + ci
    // Spec 2.7
    let sigma_i = alpha * private_share - (beta * a_i - c_i);

    Ok(PresignOutput {
        big_r,
        k: k_i,
        sigma: sigma_i,
    })
```

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L23-34)
```rust
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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L41-49)
```rust
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our share of the nonce value.
    pub k: Scalar,
    /// Our share of the sigma value.
    pub sigma: Scalar,
}
```
