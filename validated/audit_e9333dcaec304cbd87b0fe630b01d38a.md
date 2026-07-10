### Title
ECDSA `Signature` Point Malleability: `big_r` Negation Produces a Second Valid Signature Without Threshold Protocol Participation — (File: `src/ecdsa/mod.rs`)

### Summary

The library's `Signature` struct stores the full nonce point `big_r: AffinePoint`, but `Signature::verify` only uses its x-coordinate for verification. Because the x-coordinate is identical for both `R = (x, y)` and `-R = (x, -y)`, an external observer who receives any valid threshold signature `(big_r, s)` can trivially produce a second, distinct, fully-verifying signature `(-big_r, s)` for the same message and public key — without any interaction with the threshold protocol.

### Finding Description

`Signature::verify` in `src/ecdsa/mod.rs` extracts only the x-coordinate of `big_r`:

```rust
pub fn verify(&self, public_key: &AffinePoint, msg_hash: &Scalar) -> bool {
    let r: Scalar = x_coordinate(&self.big_r);   // only x is used
    ...
    let reproduced = (ProjectivePoint::GENERATOR * (*msg_hash * s_inv))
        + (ProjectivePoint::from(*public_key) * (r * s_inv));
    x_coordinate(&reproduced.into()) == r
}
``` [1](#0-0) 

The struct itself stores the full affine point:

```rust
pub struct Signature {
    pub big_r: AffinePoint,   // full point, y-coordinate included
    pub s: Scalar,
}
``` [2](#0-1) 

Both signing implementations (OT-based and Robust) produce `big_r` directly from the rerandomized presignature without normalizing the y-coordinate:

```rust
let sig = Signature {
    big_r: presignature.big_r,
    s,
};
``` [3](#0-2) [4](#0-3) 

The low-S normalization applied to `s` is the only canonicalization performed:

```rust
s.conditional_assign(&(-s), s.is_high());
``` [5](#0-4) [6](#0-5) 

No equivalent normalization is applied to `big_r`. Because `x_coordinate(-R) == x_coordinate(R)`, the pair `(-big_r, s)` passes `verify` identically to `(big_r, s)`.

### Impact Explanation

An attacker who observes any valid threshold signature `(big_r, s)` can construct a second valid signature `(-big_r, s)` — a distinct `Signature` value that passes `Signature::verify` — without any participation in the threshold protocol and without knowledge of any secret material. This constitutes unauthorized creation of a valid threshold signature.

Any downstream system that uses the full `Signature` struct (or its `big_r` field) as a unique identifier for replay protection (e.g., storing "seen signatures" to prevent double-spend or replay) will treat `(big_r, s)` and `(-big_r, s)` as distinct, both-valid signatures, allowing the attacker to replay a transaction that was supposed to be consumed.

**Impact: Critical** — unauthorized creation of a valid threshold signature without threshold protocol participation.

### Likelihood Explanation

The attack is trivial: negating the y-coordinate of an affine point is a single field negation. No secret material, no interaction with signers, no cryptographic computation beyond basic elliptic curve arithmetic. Any party that receives a signed output from this library can immediately produce the malleable variant. Likelihood is **High**.

### Recommendation

Canonicalize `big_r` in `Signature::verify` (and/or at signing time) by rejecting or normalizing signatures where `big_r` has an odd y-coordinate (analogous to BIP-340's even-y convention):

```rust
pub fn verify(&self, public_key: &AffinePoint, msg_hash: &Scalar) -> bool {
    // Reject non-canonical big_r (odd y-coordinate)
    if self.big_r.y_is_odd().into() {
        return false;
    }
    let r: Scalar = x_coordinate(&self.big_r);
    ...
}
```

Alternatively, normalize `big_r` during signing (negate both `big_r` and `s` if `big_r.y` is odd, keeping `s` low). At minimum, add a documented warning that `big_r` is not canonicalized and that downstream systems must not use the full `Signature` struct as a unique identifier for replay protection.

### Proof of Concept

```rust
// Attacker receives a valid threshold signature
let valid_sig: Signature = /* output of threshold signing protocol */;
assert!(valid_sig.verify(&public_key, &msg_hash));

// Attacker negates big_r (trivial elliptic curve operation)
let malleable_big_r = (-ProjectivePoint::from(valid_sig.big_r)).to_affine();
let malleable_sig = Signature {
    big_r: malleable_big_r,
    s: valid_sig.s,
};

// Both verify correctly — two distinct Signature values, same (msg, pk)
assert!(malleable_sig.verify(&public_key, &msg_hash));
assert_ne!(valid_sig.big_r, malleable_sig.big_r); // different byte representations

// A replay-protection system storing seen big_r values would treat these as distinct,
// allowing the attacker to replay a "consumed" signature.
```

### Citations

**File:** src/ecdsa/mod.rs (L56-61)
```rust
pub struct Signature {
    /// This is the entire first point.
    pub big_r: AffinePoint,
    /// This is the second scalar, normalized to be in the lower range.
    pub s: Scalar,
}
```

**File:** src/ecdsa/mod.rs (L65-79)
```rust
    pub fn verify(&self, public_key: &AffinePoint, msg_hash: &Scalar) -> bool {
        let r: Scalar = x_coordinate(&self.big_r);
        if r.is_zero().into() || self.s.is_zero().into() {
            return false;
        }
        // Check if s has been normalized
        if self.s.is_high().into() {
            return false;
        }
        // tested earlier is not zero, so inversion will not raise an error and unwrap cannot panic
        let s_inv = self.s.invert_vartime().unwrap();
        let reproduced = (ProjectivePoint::GENERATOR * (*msg_hash * s_inv))
            + (ProjectivePoint::from(*public_key) * (r * s_inv));
        x_coordinate(&reproduced.into()) == r
    }
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L121-121)
```rust
    s.conditional_assign(&(-s), s.is_high());
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L123-126)
```rust
    let sig = Signature {
        big_r: presignature.big_r,
        s,
    };
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L152-152)
```rust
    s.conditional_assign(&(-s), s.is_high());
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L154-157)
```rust
    let sig = Signature {
        big_r: presignature.big_r,
        s,
    };
```
