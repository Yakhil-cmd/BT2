The claimed path is real. Let me trace it precisely.

**Can `PolynomialCommitment::new()` accept an identity constant term?**

`PolynomialCommitment::new()` uses `rposition` to find the last non-identity element and trims trailing identities. It only rejects the all-identity case. A polynomial like `[identity, non-identity, ...]` passes construction. [1](#0-0) 

**Does `eval_at_zero()` check for identity?**

No. It simply returns `self.coefficients.first()` — no identity guard. [2](#0-1) 

**What happens in the verifier path (Spec 3.3+3.4)?**

After receiving `PolynomialCommitmentsMessageMany`, the verifier:
1. Checks degree — passes if correct
2. Checks hash commitment — passes if the malicious party committed to this polynomial in round 1 (they can)
3. Calls `dlog::verify()` with `their_big_e.eval_at_zero()?.value()` as the public point [3](#0-2) 

**What happens in `dlog::verify()` with an identity public point?**

`verify()` calls `statement.encode()?` first. `encode()` calls `<C::Group as Group>::serialize(self.public)`. For secp256k1, the identity (point at infinity) is not serializable — this returns `Err`, which `encode()` maps to `Err(ProtocolError::PointSerialization)`, propagating via `?` through `verify()` and back into `do_generation_many`. [4](#0-3) [5](#0-4) 

**Correction on the specific file cited in the question:**

The question attributes the failure to `dlogeq.rs -> Statement::encode() -> element_into`. That path is also reachable (line 478 uses `big_e_j_zero.index(from)?.value()` as `public0` in a `dlogeq::Statement`), but it is never reached because `dlog::verify()` at line 368 fails first with the same identity input. The root cause is in `dlog.rs`, not `dlogeq.rs`. [6](#0-5) [7](#0-6) 

**Is the error fatal?**

Yes. The `?` operator propagates `Err(ProtocolError::PointSerialization)` out of `do_generation_many`, aborting the honest verifier's entire triple generation session. The malicious party can repeat this on every restart, making the denial persistent. [8](#0-7) 

---

### Title
Malicious participant can permanently abort honest parties' triple generation by sending a `PolynomialCommitment` with identity constant term — (`src/ecdsa/ot_based_ecdsa/triples/generation.rs`, `src/crypto/proofs/dlog.rs`)

### Summary
A malicious participant in triple generation can construct a `PolynomialCommitment` for `big_e` whose constant term is the group identity. This passes all structural checks (`PolynomialCommitment::new`, degree check, hash commitment check) but causes `dlog::Statement::encode()` to fail with `Err(ProtocolError::PointSerialization)` when the honest verifier attempts to verify the accompanying dlog proof, permanently aborting the session.

### Finding Description
`PolynomialCommitment::new()` only rejects the all-identity case; a polynomial `[identity, non-identity, ...]` is accepted. `eval_at_zero()` returns the first coefficient without any identity check. In `do_generation_many` (Spec 3.3+3.4), the verifier constructs `dlog::Statement { public: &their_big_e.eval_at_zero()?.value() }` and calls `dlog::verify()`. Inside `verify()`, `statement.encode()?` calls `Group::serialize(identity)`, which fails for secp256k1, returning `Err(ProtocolError::PointSerialization)` that propagates via `?` and aborts the session.

The attacker must:
1. Construct `big_e` with `coefficients = [identity, r*G]` for any random `r` (passes `PolynomialCommitment::new`)
2. Commit to it in round 1 (hash commitment)
3. Reveal it in round 2 — the commitment check passes (consistent)
4. Degree check passes (degree = 1 = threshold - 1 for threshold=2)
5. `dlog::verify()` aborts the honest verifier

### Impact Explanation
Every honest participant who receives this message has their triple generation session permanently aborted. Since triples are required for every ECDSA presignature, this is a permanent denial of signing capability for any session involving the malicious party.

### Likelihood Explanation
Any participant in the protocol can execute this. No cryptographic assumption needs to be broken. The attack requires only constructing a specific polynomial commitment, which is trivial. It is repeatable on every restart.

### Recommendation
In `do_generation_many`, before constructing `dlog::Statement`, explicitly check that `their_big_e.eval_at_zero()?.value() != C::Group::identity()` and return `Err(ProtocolError::AssertionFailed(...))` attributed to `from` rather than propagating a serialization error. Similarly guard `their_big_f.eval_at_zero()?.value()`. Alternatively, add an identity check inside `PolynomialCommitment::eval_at_zero()` or inside `dlog::verify()` analogous to the existing guard in `dlogeq::verify()`. [9](#0-8) 

### Proof of Concept
```rust
// Construct big_e with identity constant term
let identity = <Secp256K1Sha256 as frost_core::Ciphersuite>::Group::identity();
let r = frost_core::random_nonzero::<Secp256K1Sha256, _>(&mut rng);
let non_identity = ProjectivePoint::GENERATOR * r;
let big_e_malicious = PolynomialCommitment::new(&[
    CoefficientCommitment::new(identity),
    CoefficientCommitment::new(non_identity),
]).unwrap(); // passes: not all-identity

// eval_at_zero returns identity
let zero_eval = big_e_malicious.eval_at_zero().unwrap().value();
assert_eq!(zero_eval, identity);

// dlog::verify fails with PointSerialization
let statement = dlog::Statement::<Secp256K1Sha256> { public: &zero_eval };
let dummy_proof = dlog::Proof { e: ..., s: ... };
let result = dlog::verify(&mut transcript, statement, &dummy_proof);
assert!(matches!(result, Err(ProtocolError::PointSerialization)));
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L109-116)
```rust
async fn do_generation_many<const N: usize>(
    comms: Comms,
    participants: ParticipantList,
    me: Participant,
    threshold: ReconstructionLowerBound,
    mut rng: impl CryptoRngCore,
) -> Result<TripleGenerationOutputMany, ProtocolError> {
    assert!(N > 0);
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L365-376)
```rust
                let statement0 = dlog::Statement::<C> {
                    public: &their_big_e.eval_at_zero()?.value(),
                };
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L477-491)
```rust
                let statement = dlogeq::Statement::<C> {
                    public0: &big_e_j_zero.index(from)?.value(),
                    generator1: &big_f.eval_at_zero()?.value(),
                    public1: &big_c_j,
                };

                if !dlogeq::verify(
                    &mut transcript.fork(b"dlogeq0", &from.bytes()),
                    statement,
                    their_phi_proof,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlogeq proof from {from:?} failed to verify"
                    )));
                }
```

**File:** src/crypto/proofs/dlog.rs (L25-37)
```rust
    fn encode(self) -> Result<Vec<u8>, ProtocolError> {
        let mut enc = Vec::new();
        enc.extend_from_slice(NEAR_DLOG_ENCODE_LABEL_STATEMENT);

        match <C::Group as Group>::serialize(self.public) {
            Ok(ser) => {
                enc.extend_from_slice(NEAR_DLOG_ENCODE_LABEL_PUBLIC);
                enc.extend_from_slice(ser.as_ref());
            }
            _ => return Err(ProtocolError::PointSerialization),
        }
        Ok(enc)
    }
```

**File:** src/crypto/proofs/dlog.rs (L87-89)
```rust
) -> Result<bool, ProtocolError> {
    transcript.message(NEAR_DLOG_STATEMENT_LABEL, &statement.encode()?);

```

**File:** src/crypto/proofs/dlogeq.rs (L50-61)
```rust
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut enc = Vec::new();
        enc.extend_from_slice(NEAR_DLOGEQ_ENCODE_LABEL_STATEMENT);
        // None of the following calls should panic as neither public and generator are identity
        let ser0 = element_into::<C>(self.public0, NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC0)?;
        let ser1 = element_into::<C>(self.generator1, NEAR_DLOGEQ_ENCODE_LABEL_GENERATOR1)?;
        let ser2 = element_into::<C>(self.public1, NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC1)?;
        enc.extend_from_slice(&ser0);
        enc.extend_from_slice(&ser1);
        enc.extend_from_slice(&ser2);
        Ok(enc)
    }
```

**File:** src/crypto/proofs/dlogeq.rs (L147-149)
```rust
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }
```
