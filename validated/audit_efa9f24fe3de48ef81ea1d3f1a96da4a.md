### Title
`dlogeq::verify` Returns Hard Error on Identity Commitment, Enabling Protocol Abort by Malicious Participant — (`src/crypto/proofs/dlogeq.rs`)

---

### Summary

A malicious participant can craft a `dlogeq::Proof` with `(e, s)` chosen so that the reconstructed commitment `big_k0 = G*s − public0*e` equals the group identity. This causes `encode_two_points` to return `Err(ProtocolError::IdentityElement)`, which propagates through `verify()` and then through the `?` operator in the triple-generation protocol, permanently aborting honest parties' execution.

---

### Finding Description

In `dlogeq::verify`, after computing the reconstructed commitments:

```rust
let big_k0 = phi0 - *statement.public0 * proof.e.0;
let big_k1 = phi1 - *statement.public1 * proof.e.0;

let enc = encode_two_points::<C>(&big_k0, &big_k1)?;
``` [1](#0-0) 

`encode_two_points` calls `C::Group::serialize` on each point, which rejects the identity element:

```rust
let mut ser1 = C::Group::serialize(point_1)
    .map_err(|_| ProtocolError::IdentityElement)?
    .as_ref()
    .to_vec();
``` [2](#0-1) 

If either `big_k0` or `big_k1` is the identity, `verify` returns `Err(ProtocolError::IdentityElement)` instead of `Ok(false)`.

The sole call site in production code uses `?` unconditionally:

```rust
if !dlogeq::verify(
    &mut transcript.fork(b"dlogeq0", &from.bytes()),
    statement,
    their_phi_proof,
)? {
``` [3](#0-2) 

This `?` propagates the `Err` out of the triple-generation function, aborting the honest party's protocol.

---

### Impact Explanation

A malicious participant can permanently prevent triple generation (and therefore ECDSA signing) for all honest parties in any session they participate in. The abort is triggered deterministically with a single crafted message.

---

### Likelihood Explanation

**High.** The attacker is a registered participant who controls their own proof bytes. The attack requires no cryptographic break:

- The attacker chose their own commitment `public0 = G*x` in round 2 (they know `x`).
- They set `s = x * e` for any nonzero `e` of their choice.
- Then `G*s − public0*e = G*(x*e) − (G*x)*e = identity`.

This is a trivial scalar arithmetic construction, executable without any special capability beyond being a protocol participant.

---

### Recommendation

In `dlogeq::verify`, treat an identity reconstructed commitment as a proof failure rather than a hard error. Replace the propagating `?` on `encode_two_points` with an explicit match:

```rust
let enc = match encode_two_points::<C>(&big_k0, &big_k1) {
    Ok(enc) => enc,
    Err(ProtocolError::IdentityElement) => return Ok(false),
    Err(e) => return Err(e),
};
```

This ensures that any attacker-supplied `(e, s)` pair that produces an identity commitment yields `Ok(false)` (proof rejected) rather than `Err` (protocol abort).

---

### Proof of Concept

```rust
// Attacker knows x such that public0 = G*x (they chose it in round 2)
// Choose any nonzero e:
let e = Scalar::from(42u64);
// Set s = x * e so that G*s - public0*e = identity:
let s = x * e;
let malicious_proof = Proof { e: SerializableScalar(e), s: SerializableScalar(s) };

// Honest verifier calls:
let result = dlogeq::verify(&mut transcript, statement, &malicious_proof);
// result == Err(ProtocolError::IdentityElement)  ← aborts the protocol
```

The `?` at `generation.rs:487` propagates this `Err` out of the triple-generation task, permanently aborting the honest party's session.

### Citations

**File:** src/crypto/proofs/dlogeq.rs (L87-90)
```rust
    let mut ser1 = C::Group::serialize(point_1)
        .map_err(|_| ProtocolError::IdentityElement)?
        .as_ref()
        .to_vec();
```

**File:** src/crypto/proofs/dlogeq.rs (L153-157)
```rust
    let (phi0, phi1) = statement.phi(&proof.s.0);
    let big_k0 = phi0 - *statement.public0 * proof.e.0;
    let big_k1 = phi1 - *statement.public1 * proof.e.0;

    let enc = encode_two_points::<C>(&big_k0, &big_k1)?;
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L483-491)
```rust
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
