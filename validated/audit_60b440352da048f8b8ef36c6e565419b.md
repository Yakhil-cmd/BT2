### Title
Same Beaver Triple Used for Both `triple0` and `triple1` Leaks the Nonce, Enabling Full Private Key Extraction - (File: `src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

The OT-based ECDSA `presign()` function accepts a `PresignArguments` struct containing two independent Beaver triples (`triple0`, `triple1`). No check is performed to ensure these two triples are distinct. If a caller supplies the same triple for both slots, the masking property of the Cait-Sith protocol collapses: the publicly broadcast value `alpha` becomes `2k` instead of `k + a`, directly revealing the nonce `k` to every presign participant. With `k` known, any participant can recover the aggregate private key `x` from the resulting ECDSA signature.

---

### Finding Description

The `presign()` entry point in `src/ecdsa/ot_based_ecdsa/presign.rs` validates threshold consistency between the two triples but never checks that `triple0` and `triple1` are distinct:

```rust
// src/ecdsa/ot_based_ecdsa/presign.rs  lines 43-47
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(
        "New threshold must match the threshold of both triples".to_string(),
    ));
}
```

No guard of the form `args.triple0.1 != args.triple1.1` exists anywhere in `presign()` or `do_presign()`.

Inside `do_presign()`, the two triples play distinct cryptographic roles:

- **`triple0`** supplies the nonce material: `k_i = triple0.0.a`, `e_i = triple0.0.c`, and public commitments `K = triple0.1.big_a`, `D = triple0.1.big_b`, `E = triple0.1.big_c`.
- **`triple1`** supplies the masking material: `a_i = triple1.0.a`, `b_i = triple1.0.b`, `c_i = triple1.0.c`, and public commitments `A = triple1.1.big_a`, `B = triple1.1.big_b`.

```rust
// src/ecdsa/ot_based_ecdsa/presign.rs  lines 72-89
let a_i = args.triple1.0.a;
let b_i = args.triple1.0.b;
let c_i = args.triple1.0.c;
let big_a: ProjectivePoint = args.triple1.1.big_a.into();
let big_b: ProjectivePoint = args.triple1.1.big_b.into();

let k_i = args.triple0.0.a;
let e_i = args.triple0.0.c;
let big_k: ProjectivePoint = args.triple0.1.big_a.into();
let big_d = args.triple0.1.big_b;
let big_e = args.triple0.1.big_c;
```

In Round 2, each party broadcasts `alpha_i = k_prime_i + a_prime_i`:

```rust
// src/ecdsa/ot_based_ecdsa/presign.rs  lines 136-143
let alpha_i: Scalar = k_prime_i + a_prime_i;
let beta_i: Scalar = x_prime_i + b_prime_i;
let wait1 = chan.next_waitpoint();
chan.send_many(wait1, &(alpha_i, beta_i))?;
```

When `triple0 == triple1`, `k_i = a_i` for every party, so:

```
alpha_i = lambda_i * k_i + lambda_i * a_i = 2 * lambda_i * k_i
alpha   = SUM_i alpha_i = 2 * SUM_i (lambda_i * k_i) = 2k
```

The aggregate `alpha = 2k` is broadcast to all participants. Since `2` is invertible in the scalar field, every participant immediately learns `k = alpha / 2`.

The existing consistency check `alpha*G == K + A` still passes because `K = A = k*G`, so `K + A = 2k*G = alpha*G`. The protocol completes without error, producing a valid-looking `PresignOutput`.

---

### Impact Explanation

Once `k` is known, any participant who observes the final ECDSA signature `(R, s)` can recover the aggregate private key `x`. The signing equation used by this library is `s = k * (H(m) + r * x)` (per `docs/ecdsa/ot_based_ecdsa/signing.md` line 4), so:

```
x = (s / k - H(m)) / r
```

All quantities on the right-hand side are known: `s` and `r` are public in the signature, `H(m)` is the message hash, and `k = alpha / 2` is learned during presign. This constitutes **full extraction of the aggregate private signing key**, matching the Critical impact tier: *Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, or nonce material*.

---

### Likelihood Explanation

The `presign()` function and `PresignArguments` struct are part of the public library API. Any caller constructing `PresignArguments` can set `triple0` and `triple1` to the same value — either accidentally (e.g., reusing a triple from a pool by mistake) or maliciously (a compromised orchestrator or participant deliberately supplying identical triples to extract the key). No runtime guard prevents this. `TriplePub` already derives `PartialEq`/`Eq`, so the check is trivially implementable. The attack requires no cryptographic capability beyond calling the public API.

---

### Recommendation

Add a distinctness check in `presign()` immediately after the threshold consistency check:

```rust
// src/ecdsa/ot_based_ecdsa/presign.rs
if args.triple0.1 == args.triple1.1 {
    return Err(InitializationError::BadParameters(
        "triple0 and triple1 must be distinct; reusing the same triple leaks the nonce".to_string(),
    ));
}
```

Because `TriplePub` already derives `PartialEq` and `Eq`, this check compiles without any additional trait implementations.

---

### Proof of Concept

**Setup**: Generate one triple, clone it, and pass it as both `triple0` and `triple1`.

```rust
// Attacker constructs PresignArguments with triple0 == triple1
let (triple_pub, triple_shares) = deal(&mut rng, &participants, threshold).unwrap();
let share = triple_shares[0].clone();

let args = PresignArguments {
    triple0: (share.clone(), triple_pub.clone()),  // same triple
    triple1: (share.clone(), triple_pub.clone()),  // same triple
    keygen_out,
    threshold,
};

// presign() accepts this without error
let protocol = presign(&participants, me, args).unwrap();
// ... run protocol ...

// After presign completes, alpha = 2k is known to all participants.
// alpha is broadcast in Round 2 (wait1). Any participant reads it.
// k = alpha * 2^{-1} mod q
// With k and the final signature (R, s): x = (s/k - H(m)) / r
```

The `presign()` function at `src/ecdsa/ot_based_ecdsa/presign.rs:20-62` accepts the call without error. The `do_presign()` consistency check at line 162 (`alpha*G == K + A`) passes because `K = A` when the triples are identical. The protocol terminates normally, but `alpha = 2k` is now public among all participants, enabling full private key recovery.