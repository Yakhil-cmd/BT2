The claim is concrete and traceable. Let me verify the one remaining question — whether `PolynomialCommitment::new()` actually permits identity as the constant term (coefficient[0]).

From `src/crypto/polynomials.rs` lines 221–237:

```rust
pub fn new(coefcommitments: &[CoefficientCommitment<C>]) -> Result<Self, ProtocolError> {
    let count = coefcommitments
        .iter()
        .rposition(|x| x.value() != C::Group::identity())
        .map_or(0, |i| i + 1);

    if count == 0 {
        return Err(ProtocolError::EmptyOrZeroCoefficients);
    }

    let new_coefficients: Vec<_> = coefcommitments.iter().take(count).copied().collect();
    Ok(Self { coefficients: new_coefficients })
}
```

`rposition` finds the **last** non-identity element. For input `[identity, G, G]`, it returns index 2, `count = 3`, and all three coefficients are kept — including the identity at index 0. The constant term is **not** validated against identity.

---

### Title
Identity Constant Term in `PolynomialCommitment` Causes `dlog::verify` to Abort Triple Generation for All Honest Parties — (`src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

### Summary

A malicious participant can craft a `PolynomialCommitment` whose constant term (coefficient[0]) is the group identity element. When honest parties call `their_big_e.eval_at_zero()?.value()` and pass the result as the `dlog::Statement` public point, `Statement::encode()` fails with `ProtocolError::PointSerialization` because `C::Group::serialize` rejects the identity. This error propagates via `?` out of `dlog::verify` and aborts the entire `do_generation_many` future for every honest participant.

### Finding Description

**Step 1 — Crafting the malicious polynomial commitment.**

`PolynomialCommitment::new()` strips trailing identity elements from the *back* of the coefficient vector, but does not validate the constant term (index 0): [1](#0-0) 

A vector like `[identity, G, G]` passes validation because `rposition` finds the last non-identity at index 2, so `count = 3` and all three coefficients are retained. The identity constant term survives.

Deserialization calls `Self::new()` directly, so a network-delivered polynomial with an identity constant term is accepted: [2](#0-1) 

**Step 2 — Bypassing the hash commitment check.**

Before sending the polynomial, each participant sends a hash commitment in round 1. The check at lines 353–363 verifies consistency between the hash commitment and the revealed polynomial: [3](#0-2) 

The malicious participant controls *both* the round-1 hash commitment and the round-2 polynomial, so they simply commit to the malicious polynomial (identity constant term, non-identity higher-degree coefficients) in round 1. The check passes.

**Step 3 — `eval_at_zero()` returns the identity without validation.**

`PolynomialCommitment::eval_at_zero()` returns the first coefficient unconditionally: [4](#0-3) 

**Step 4 — `dlog::Statement::encode()` fails on the identity.**

The statement is constructed directly from the result: [5](#0-4) 

Inside `dlog::verify`, `statement.encode()` is called first: [6](#0-5) 

`encode()` calls `C::Group::serialize(self.public)`, which returns `Err` for the identity element, causing `encode()` to return `Err(ProtocolError::PointSerialization)`: [7](#0-6) 

**Step 5 — Error propagates and aborts the protocol.**

The `?` at line 372 propagates the error out of the `parallel_to_multiplication_task` async block, which is joined with `multiplication_task` via `try_join`. The entire `do_generation_many` function returns `Err`, aborting triple generation for all honest parties: [8](#0-7) 

### Impact Explanation

Every honest party processing the malicious participant's `PolynomialCommitmentsMessageMany` message will have their `do_generation_many` future return an error. Triple generation is permanently denied for the entire session. Since triples are required for OT-based ECDSA presigning, this blocks all subsequent signing operations.

### Likelihood Explanation

Any participant in the protocol can mount this attack. No special privileges are required — only the ability to send a crafted `PolynomialCommitmentsMessageMany` message. The attack is deterministic and requires no brute force or cryptographic assumptions.

### Recommendation

Add an explicit identity check before constructing the `dlog::Statement`. For example, in `generation.rs` before line 365:

```rust
if their_big_e.eval_at_zero()?.value() == C::Group::identity() {
    return Err(ProtocolError::AssertionFailed(format!(
        "identity constant term in polynomial from {from:?}"
    )));
}
```

Alternatively, enforce in `PolynomialCommitment::new()` that the constant term is never the identity, or have `dlog::verify` treat a `PointSerialization` error on the statement as a proof failure (`Ok(false)`) rather than a hard abort.

### Proof of Concept

```rust
// Craft a PolynomialCommitment with identity as constant term
let identity = <Secp256K1Sha256 as frost_core::Ciphersuite>::Group::identity();
let generator = <Secp256K1Sha256 as frost_core::Ciphersuite>::Group::generator();
let coeffs = vec![
    CoefficientCommitment::new(identity),   // constant term = identity
    CoefficientCommitment::new(generator),  // degree-1 term = G (non-identity, so new() accepts)
];
let malicious_poly = PolynomialCommitment::<Secp256K1Sha256>::new(&coeffs).unwrap();

// eval_at_zero returns identity without error
let zero_val = malicious_poly.eval_at_zero().unwrap().value();
assert_eq!(zero_val, identity);

// dlog::verify returns PointSerialization error, not Ok(false)
let statement = dlog::Statement::<Secp256K1Sha256> { public: &zero_val };
let dummy_proof = dlog::Proof { e: SerializableScalar(Scalar::from(1u64)), s: SerializableScalar(Scalar::from(1u64)) };
let result = dlog::verify(&mut Transcript::new(b"test"), statement, &dummy_proof);
assert!(matches!(result, Err(ProtocolError::PointSerialization)));
// This Err propagates via ? in generation.rs, aborting the protocol for all honest parties.
```

### Citations

**File:** src/crypto/polynomials.rs (L221-237)
```rust
    pub fn new(coefcommitments: &[CoefficientCommitment<C>]) -> Result<Self, ProtocolError> {
        // count the number of zero coeffs before spotting the first non-zero from the back
        let count = coefcommitments
            .iter()
            .rposition(|x| x.value() != C::Group::identity())
            .map_or(0, |i| i + 1);

        if count == 0 {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }

        let new_coefficients: Vec<_> = coefcommitments.iter().take(count).copied().collect();

        Ok(Self {
            coefficients: new_coefficients,
        })
    }
```

**File:** src/crypto/polynomials.rs (L279-284)
```rust
    pub fn eval_at_zero(&self) -> Result<CoefficientCommitment<C>, ProtocolError> {
        self.coefficients
            .first()
            .copied()
            .ok_or(ProtocolError::EmptyOrZeroCoefficients)
    }
```

**File:** src/crypto/polynomials.rs (L382-391)
```rust
impl<'de, C: Ciphersuite> Deserialize<'de> for PolynomialCommitment<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let coefficients = Vec::<CoefficientCommitment<C>>::deserialize(deserializer)?;
        Self::new(&coefficients)
            .map_err(|err| serde::de::Error::custom(format!("ProtocolError: {err}")))
    }
}
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L353-364)
```rust
                if !all_commitments
                    .index(from)?
                    .check(
                        &(&their_big_e, &their_big_f, &their_big_l),
                        their_randomizer,
                    )
                    .map_err(|_| ProtocolError::PointSerialization)?
                {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "commitment from {from:?} did not match revealed F"
                    )));
                }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L365-367)
```rust
                let statement0 = dlog::Statement::<C> {
                    public: &their_big_e.eval_at_zero()?.value(),
                };
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L368-376)
```rust
                if !dlog::verify(
                    &mut transcript.fork(b"dlog0", &from.bytes()),
                    statement0,
                    their_phi_proof0,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlog proof from {from:?} failed to verify"
                    )));
                }
```

**File:** src/crypto/proofs/dlog.rs (L29-34)
```rust
        match <C::Group as Group>::serialize(self.public) {
            Ok(ser) => {
                enc.extend_from_slice(NEAR_DLOG_ENCODE_LABEL_PUBLIC);
                enc.extend_from_slice(ser.as_ref());
            }
            _ => return Err(ProtocolError::PointSerialization),
```

**File:** src/crypto/proofs/dlog.rs (L88-88)
```rust
    transcript.message(NEAR_DLOG_STATEMENT_LABEL, &statement.encode()?);
```
