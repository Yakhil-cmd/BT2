### Title
Incorrect `&&` Operator in `set_nonzero_constant` and `set_non_identity_constant` Bypasses Zero-Value Guard for Multi-Coefficient Polynomials — (`src/crypto/polynomials.rs`)

---

### Summary

Both `Polynomial::set_nonzero_constant` and `PolynomialCommitment::set_non_identity_constant` use `&&` to combine two conditions when checking whether to reject a zero/identity constant term. Because the second condition (`coefficients_len == 1`) is almost never true in threshold protocols (where polynomials always have degree ≥ 1), the zero-value guard is silently bypassed for every real-world call. A malicious participant can exploit this to inject a zero constant term into a triple-generation polynomial, corrupting the Beaver triple and producing an unusable presignature that honest parties accept.

---

### Finding Description

In `src/crypto/polynomials.rs`, both setter functions share the same structural bug:

**`Polynomial::set_nonzero_constant`** (lines 181–193):
```rust
/// Set the constant value of this polynomial to a new scalar
/// Abort if the output polynomial would be zero or empty
pub fn set_nonzero_constant(&mut self, v: Scalar<C>) -> Result<(), ProtocolError> {
    let coefficients_len = self.coefficients.len();
    self.coefficients
        .first_mut()
        .map_or(Err(ProtocolError::EmptyOrZeroCoefficients), |first| {
            if v == <C::Group as Group>::Field::zero() && coefficients_len == 1 {
                Err(ProtocolError::EmptyOrZeroCoefficients)
            } else {
                *first = v;
                Ok(())
            }
        })
}
```

**`PolynomialCommitment::set_non_identity_constant`** (lines 354–369):
```rust
/// Set the constant value of this polynomial to a new group element
/// Aborts if the output polynomial would be the identity or empty
pub fn set_non_identity_constant(
    &mut self,
    v: CoefficientCommitment<C>,
) -> Result<(), ProtocolError> {
    let coefficients_len = self.coefficients.len();
    self.coefficients
        .first_mut()
        .map_or(Err(ProtocolError::EmptyOrZeroCoefficients), |first| {
            if v.value() == C::Group::identity() && coefficients_len == 1 {
                Err(ProtocolError::EmptyOrZeroCoefficients)
            } else {
                *first = v;
                Ok(())
            }
        })
}
```

The documented intent of both functions is to **abort if the constant term would be zero/identity**. The `&&` operator means the guard only fires when *both* `v == zero` **and** `coefficients_len == 1`. In every threshold protocol call (threshold ≥ 2 implies polynomial degree ≥ 1, so `coefficients_len ≥ 2`), the second conjunct is always `false`, making the entire guard permanently dead code. A zero scalar or identity group element is silently written as the constant term.

Both functions are called in `src/ecdsa/ot_based_ecdsa/triples/generation.rs`, which is the OT-based Beaver triple generation protocol. The constant term of the polynomial in that context is the participant's own share of the triple value (`a_i` or `b_i`). Setting it to zero produces a structurally valid but cryptographically degenerate triple.

The existing unit test at line 881–883 only exercises the `coefficients_len == 1` path (degree-0 polynomial), so the bug is not caught by the test suite:

```rust
let mut poly_abort = Polynomial::<C>::generate_polynomial(Some(one), 0, &mut rng).unwrap();
let zero = <<C as frost_core>::Group as Group>::Field::zero();
assert!(poly_abort.set_nonzero_constant(zero).is_err()); // only tests len==1
```

---

### Impact Explanation

**High — Corruption of presign outputs so honest parties accept unusable cryptographic outputs.**

A malicious participant in the OT-based ECDSA triple generation protocol can supply a zero value to `set_nonzero_constant` on a polynomial of degree ≥ 1. The guard is bypassed, the constant term (the participant's triple share) is silently set to zero, and the resulting `TripleShare` / `TriplePub` output is accepted by all honest parties as valid. Any presignature built on this triple will be cryptographically invalid, permanently denying signing for the session that consumed the corrupted triple.

---

### Likelihood Explanation

**Medium.** The triple generation protocol is called by every participant before signing. A single malicious participant who controls the value passed to `set_nonzero_constant` (their own share contribution) can trigger this path deterministically. The polynomial degree in any real deployment is always ≥ 1, so the bypass is unconditional once the attacker provides a zero value. The only mitigating factor is that the attacker must be an enrolled participant in the protocol session.

---

### Recommendation

Replace the `&&` compound condition with a standalone zero/identity check in both functions. The `coefficients_len == 1` sub-condition is irrelevant to the stated invariant ("constant must be non-zero") and should be removed:

```rust
// Polynomial::set_nonzero_constant — fix
if v == <C::Group as Group>::Field::zero() {
    return Err(ProtocolError::EmptyOrZeroCoefficients);
}
*first = v;
Ok(())

// PolynomialCommitment::set_non_identity_constant — fix
if v.value() == C::Group::identity() {
    return Err(ProtocolError::EmptyOrZeroCoefficients);
}
*first = v;
Ok(())
```

Add a regression test that calls `set_nonzero_constant` with `v = 0` on a polynomial of degree ≥ 1 and asserts the result is `Err`.

---

### Proof of Concept

1. In `src/ecdsa/ot_based_ecdsa/triples/generation.rs`, the protocol calls `set_nonzero_constant` on a polynomial generated with `generate_polynomial(…, degree ≥ 1, …)`, so `coefficients_len ≥ 2`.
2. A malicious participant supplies `v = Scalar::zero()` as their share contribution.
3. The guard `v == zero && coefficients_len == 1` evaluates to `true && false = false`.
4. The `else` branch executes: `*first = zero_scalar; Ok(())`.
5. The polynomial's constant term is now zero; `eval_at_zero()` returns `0`.
6. The resulting `TripleShare` carries `a_i = 0` (or `b_i = 0`).
7. Honest parties reconstruct a triple where the interpolated `a = 0`, making every presignature derived from it invalid.
8. Signing fails for all honest parties who consumed the corrupted triple. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/crypto/polynomials.rs (L179-193)
```rust
    /// Set the constant value of this polynomial to a new scalar
    /// Abort if the output polynomial would be zero or empty
    pub fn set_nonzero_constant(&mut self, v: Scalar<C>) -> Result<(), ProtocolError> {
        let coefficients_len = self.coefficients.len();
        self.coefficients
            .first_mut()
            .map_or(Err(ProtocolError::EmptyOrZeroCoefficients), |first| {
                if v == <C::Group as Group>::Field::zero() && coefficients_len == 1 {
                    Err(ProtocolError::EmptyOrZeroCoefficients)
                } else {
                    *first = v;
                    Ok(())
                }
            })
    }
```

**File:** src/crypto/polynomials.rs (L352-369)
```rust
    /// Set the constant value of this polynomial to a new group element
    /// Aborts if the output polynomial would be the identity or empty
    pub fn set_non_identity_constant(
        &mut self,
        v: CoefficientCommitment<C>,
    ) -> Result<(), ProtocolError> {
        let coefficients_len = self.coefficients.len();
        self.coefficients
            .first_mut()
            .map_or(Err(ProtocolError::EmptyOrZeroCoefficients), |first| {
                if v.value() == C::Group::identity() && coefficients_len == 1 {
                    Err(ProtocolError::EmptyOrZeroCoefficients)
                } else {
                    *first = v;
                    Ok(())
                }
            })
    }
```

**File:** src/crypto/polynomials.rs (L880-884)
```rust
        let one = <<C as frost_core::Ciphersuite>::Group as Group>::Field::one();
        let mut poly_abort = Polynomial::<C>::generate_polynomial(Some(one), 0, &mut rng).unwrap();
        let zero = <<C as frost_core::Ciphersuite>::Group as Group>::Field::zero();
        assert!(poly_abort.set_nonzero_constant(zero).is_err());
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L1-30)
```rust
use frost_core::serialization::SerializableScalar;
use frost_core::Ciphersuite;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::participants::{Participant, ParticipantList, ParticipantMap};
use crate::thresholds::ReconstructionLowerBound;
use crate::{
    crypto::{
        commitment::{commit, Commitment},
        hash::{hash, HashOutput},
        proofs::{dlog, dlogeq, strobe_transcript::Transcript},
        random::Randomness,
    },
    ecdsa::{
        CoefficientCommitment, Polynomial, PolynomialCommitment, ProjectivePoint, Scalar,
        Secp256K1Sha256,
    },
    errors::{InitializationError, ProtocolError},
    protocol::{
        helpers::recv_from_others,
        internal::{make_protocol, Comms},
        Protocol,
    },
};

use super::{multiplication::multiplication_many, TriplePub, TripleShare};

/// Creates a transcript and internally encodes the following data:
///     LABEL, NAME, Participants, threshold
```
