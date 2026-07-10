### Title
Unvalidated Zero Entropy in `RerandomizationArguments` Defeats Wagner Attack Protection — (File: src/ecdsa/mod.rs)

---

### Summary

`RerandomizationArguments::new()` in `src/ecdsa/mod.rs` accepts a caller-supplied `entropy: [u8; 32]` field with no validation that it is non-zero or unpredictable. This entropy is the sole source of randomness fed into HKDF to derive the rerandomization scalar `delta`. If a caller passes `[0u8; 32]`, `delta` becomes fully deterministic from public inputs, making the rerandomized nonce `R' = delta * R` predictable to any observer — directly defeating the Wagner attack protection that rerandomization is designed to provide.

---

### Finding Description

The `RerandomizationArguments` struct documents its `entropy` field as "Fresh, Unpredictable, and Public source of entropy": [1](#0-0) 

In `derive_randomness()`, this entropy is used as the sole IKM for HKDF: [2](#0-1) 

The SALT is a hardcoded constant: [3](#0-2) 

All other inputs to the HKDF `expand` call — `pk`, `tweak`, `msg_hash`, `big_r`, `participants` — are public values: [4](#0-3) 

If `entropy = [0u8; 32]`, the HKDF output is entirely deterministic from public data. The resulting `delta` is predictable to any party who observes the signing context. The rerandomized nonce `R' = delta * R` is therefore also predictable, and the rerandomized secret shares `k' = k * delta⁻¹` and `sigma' = (sigma + tweak * k) * delta⁻¹` are computable by anyone who knows `delta`.

The constructor performs no validation: [5](#0-4) 

The same zero-entropy pattern appears in the library's own public test-utility generator, confirming the API is trivially misused: [6](#0-5) 

Both the OT-based and robust ECDSA rerandomization paths consume this same `derive_randomness()` result: [7](#0-6) [8](#0-7) 

---

### Impact Explanation

The rerandomization step exists specifically to prevent Wagner attacks, as cited in the codebase's own documentation referencing [GS21]: [9](#0-8) [10](#0-9) 

The Wagner attack allows an adversary who can request many presignatures and adaptively choose messages to forge a valid ECDSA signature without knowing any secret share. The rerandomization scalar `delta` is the only mechanism preventing this: it makes `R'` unpredictable even when the presignature `R` is known in advance.

With `entropy = [0u8; 32]`, `delta` is a fixed function of public values `(pk, tweak, msg_hash, big_r, participants)`. An attacker who controls the signing context (e.g., a malicious coordinator constructing `RerandomizationArguments`) can precompute `delta` for any future signing session, predict all `R'` values across many presignatures, and execute a Wagner attack to produce an unauthorized valid threshold signature over attacker-chosen messages.

**Impact: Critical — Unauthorized creation of a valid threshold signature for attacker-chosen inputs.**

---

### Likelihood Explanation

`RerandomizationArguments::new()` is a public API. Any party constructing the signing arguments — typically the coordinator or the application layer — can pass `entropy = [0u8; 32]`. No runtime check prevents this. The library's own `test_generators.rs` does exactly this, demonstrating the misuse path requires zero effort. A malicious coordinator in a threshold signing session is an explicitly documented threat in this library's security model (the robust ECDSA scheme is designed to tolerate up to `MaxMalicious` Byzantine participants). The coordinator role is assigned externally and is not cryptographically enforced to be honest.

---

### Recommendation

1. **Validate entropy at construction time**: Reject `entropy == [0u8; 32]` in `RerandomizationArguments::new()` with a clear error.
2. **Prefer internal entropy generation**: Rather than accepting caller-supplied entropy, generate it internally via a CSPRNG (`OsRng`) inside `derive_randomness()` or `new()`, removing the caller's ability to supply weak values.
3. **Fix the test utility**: `src/test_utils/test_generators.rs` should use `OsRng`-generated entropy rather than `[0u8; 32]` to avoid normalizing the insecure pattern.

---

### Proof of Concept

```rust
use threshold_signatures::ecdsa::{RerandomizationArguments, Tweak, ot_based_ecdsa::RerandomizedPresignOutput};

// Attacker constructs RerandomizationArguments with zero entropy
let args = RerandomizationArguments::new(
    pk,
    tweak,
    msg_hash_bytes,
    presign_out.big_r,
    participants,
    [0u8; 32],  // zero entropy — no validation rejects this
);

// delta is now fully deterministic from public inputs
let delta = args.derive_randomness().unwrap();
// R' = delta * R is predictable; attacker precomputes this for all presignatures
// With many presignatures and adaptive message selection, Wagner attack proceeds
let rerandomized = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args).unwrap();
// rerandomized.big_r == presign_out.big_r * delta  (predictable)
```

The attacker precomputes `delta` for each presignature `R` using only public values, predicts all `R'` values across a batch of presignatures, then applies the Wagner algorithm to select messages whose combined `R'` values yield a forgeable linear combination — producing an unauthorized valid ECDSA signature.

### Citations

**File:** src/ecdsa/mod.rs (L101-103)
```rust
    /// Fresh, Unpredictable, and Public source of entropy
    pub entropy: [u8; 32],
}
```

**File:** src/ecdsa/mod.rs (L111-115)
```rust
    const SALT: [u8; 32] = [
        0x32, 0x8a, 0x47, 0xc2, 0xb8, 0x79, 0x44, 0x45, 0x25, 0x5c, 0x16, 0x47, 0x60, 0x8d, 0xf5,
        0xdb, 0x85, 0xc6, 0x8b, 0xb0, 0xe7, 0x17, 0x0a, 0xbe, 0xc5, 0x34, 0xdf, 0x27, 0x64, 0xa4,
        0x58, 0x31,
    ];
```

**File:** src/ecdsa/mod.rs (L117-133)
```rust
    pub fn new(
        pk: AffinePoint,
        tweak: Tweak,
        msg_hash: [u8; 32],
        big_r: AffinePoint,
        participants: ParticipantList,
        entropy: [u8; 32],
    ) -> Self {
        Self {
            pk,
            tweak,
            msg_hash,
            big_r,
            participants,
            entropy,
        }
    }
```

**File:** src/ecdsa/mod.rs (L148-159)
```rust
        // concatenate all the bytes
        let mut concatenation = Vec::new();
        // 1 byte counter, used in the unlikely case that the hash result is 0
        concatenation.extend_from_slice(&[0u8, 1]);
        concatenation.extend_from_slice(encoded_pk);
        concatenation.extend_from_slice(encoded_tweak);
        concatenation.extend_from_slice(encoded_msg_hash);
        concatenation.extend_from_slice(encoded_big_r);
        // Append each ParticipantId's
        for participant in self.participants.participants() {
            concatenation.extend_from_slice(&participant.bytes());
        }
```

**File:** src/ecdsa/mod.rs (L161-163)
```rust
        // initiate hkdf with the salt and with some `good' entropy
        let hk = Hkdf::<sha3::Sha3_256>::new(Some(&Self::SALT), &self.entropy);

```

**File:** src/test_utils/test_generators.rs (L181-194)
```rust
            let entropy = [0u8; 32];

            let tweak = [1u8; 32];
            let tweak = ecdsa::Scalar::from_repr(tweak.into()).unwrap();
            let tweak = crate::Tweak::new(tweak);

            let rerand_args = ecdsa::RerandomizationArguments::new(
                public_key,
                tweak,
                msg_hash_bytes,
                presign_out.big_r,
                ParticipantList::new(&self.participants).unwrap(),
                entropy,
            );
```

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L66-96)
```rust
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
        }
        let delta = args.derive_randomness()?;
        if delta.is_zero().into() {
            return Err(ProtocolError::ZeroScalar);
        }

        // cannot be zero due to the previous check
        let inv_delta = delta.invert().unwrap();

        // delta . R
        let rerandomized_big_r = presignature.big_r * delta;

        //  (sigma + tweak * k) * delta^{-1}
        let rerandomized_sigma =
            (presignature.sigma + args.tweak.value() * presignature.k) * inv_delta;

        // k * delta^{-1}
        let rerandomized_k = presignature.k * inv_delta;

        Ok(Self {
            big_r: rerandomized_big_r.into(),
            k: rerandomized_k,
            sigma: rerandomized_sigma,
        })
    }
```

**File:** src/ecdsa/robust_ecdsa/mod.rs (L54-86)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
        }
        let delta = args.derive_randomness()?;
        if delta.is_zero().into() {
            return Err(ProtocolError::ZeroScalar);
        }

        // cannot be zero due to the previous check
        let inv_delta = delta.invert().unwrap();

        // delta * R
        let rerandomized_big_r = presignature.big_r * delta;

        // alpha * delta^{-1}
        let rerandomized_alpha = presignature.alpha * inv_delta;

        // (beta + c*tweak) * delta^{-1}
        let rerandomized_beta =
            (presignature.beta + presignature.c * args.tweak.value()) * inv_delta;

        Ok(Self {
            big_r: rerandomized_big_r.into(),
            alpha: rerandomized_alpha,
            beta: rerandomized_beta,
            e: presignature.e,
        })
    }
```

**File:** src/ecdsa/README.md (L10-11)
```markdown
- **`RerandomizationArguments`** -- binds a presignature to a specific signing context (public key, tweak, message hash, participants) before use. Derives a deterministic scalar `delta` via HKDF-SHA3-256 that rerandomizes the presignature nonce, mitigating Wagner attacks (see \[[GS21](https://eprint.iacr.org/2021/1330.pdf)\])
- **`KeygenOutput`** / **`Tweak`** -- Secp256k1-specialized aliases for the curve-generic DKG output types. `Tweak` allows deriving different signing keys from a single DKG output
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L139-142)
```markdown
### Presignature rerandomization and key derivation
Following [[GS21](https://eprint.iacr.org/2021/1330.pdf)]'s recommendation, we rerandomize the presignature to make the Wagner attack practically infeasible.
The key derivation is a feature that allows the holder of a secret key to derive multiple secret keys for different applications (e.g. an MPC node holding a secret key share that uses to derive several clients secret key shares).
The scheme remains correct after this rerandomization and key derivation.
```
