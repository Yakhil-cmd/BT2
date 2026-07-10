### Title
Malicious Participant Can Craft `dlogeq` Proof to Force `IdentityElement` Error, Permanently Aborting Triple Generation — (`src/ecdsa/ot_based_ecdsa/triples/generation.rs`, `src/crypto/proofs/dlogeq.rs`)

---

### Summary

A malicious participant can submit a structurally valid-looking `dlogeq` proof alongside a crafted `big_c_j` point that causes `encode_two_points` inside `dlogeq::verify` to return `Err(IdentityElement)`. Because the call site in `do_generation_many` uses the `?` operator, this error propagates as a fatal `ProtocolError`, permanently aborting triple generation for all honest parties. The attack is repeatable on every retry.

---

### Finding Description

**Step 1 — The verifier constructs the statement from attacker-controlled data.**

In round 4 of `do_generation_many`, each party verifies the dlogeq proof submitted by every other party: [1](#0-0) 

The statement is:
- `public0` = malicious party's own `big_e_j` at zero (attacker-controlled)
- `generator1` = **verifier's own** `big_f.eval_at_zero()` (broadcast in round 2, so known to attacker)
- `public1 = big_c_j` = attacker-controlled point submitted in round 4

**Step 2 — `big_c_j` is not committed to before `big_f` is revealed.**

In round 1, parties commit only to `(big_e_i, big_f_i, big_l_i)`: [2](#0-1) 

`big_c_j` is never included in any commitment. It is freely chosen and submitted in round 4 (wait4), *after* `big_f` has already been broadcast and received in round 2 (wait2).

**Step 3 — The attacker crafts `big_c_j` to make `big_k1 = identity`.**

Inside `dlogeq::verify`, the reconstructed commitment is: [3](#0-2) 

`big_k1 = generator1 * s_mal - big_c_j * e_mal`

For `big_k1` to be the group identity, the attacker sets:

```
big_c_j = generator1 * (s_mal * e_mal⁻¹)
```

Since the attacker knows `generator1` (received in round 2) and freely chooses `s_mal` and `e_mal`, this is trivially computable. The resulting `big_c_j` is a valid non-identity curve point.

**Step 4 — `encode_two_points` returns `Err(IdentityElement)` before the Fiat-Shamir check.**

`encode_two_points` is called *before* the transcript challenge is derived and compared to `proof.e`: [4](#0-3) 

When `big_k1 = identity`, `C::Group::serialize` fails, and `encode_two_points` returns `Err(IdentityElement)`. This happens before the proof's `e` value is ever checked for correctness.

**Step 5 — The `?` propagates the error fatally.** [5](#0-4) 

The `?` on `dlogeq::verify(...)` propagates `Err(ProtocolError::IdentityElement)` out of `do_generation_many`, aborting the entire triple generation protocol for all honest participants.

---

### Impact Explanation

Every honest party running `do_generation_many` (called by `generate_triple` and `generate_triple_many`) will receive a fatal `ProtocolError::IdentityElement` and abort. Since the malicious party can repeat this attack on every protocol invocation, triple generation — and therefore ECDSA presigning — is permanently denied for all honest parties as long as the malicious participant is present.

---

### Likelihood Explanation

Any single malicious participant in the protocol can execute this attack. It requires no cryptographic breaks, no leaked keys, and no external assumptions. The attacker only needs to:
1. Participate normally through round 2 to learn `big_f`
2. Compute a single scalar inversion and scalar multiplication
3. Submit the crafted `big_c_j` and proof in round 4

The attack is deterministic and succeeds with probability 1.

---

### Recommendation

Before calling `dlogeq::verify`, validate that `big_c_j` is not the identity element. More importantly, restructure `dlogeq::verify` so that an identity intermediate point during verification returns `Ok(false)` (proof rejected) rather than `Err(IdentityElement)` (fatal abort). The identity commitment `big_k1 = identity` is a proof-of-knowledge failure condition, not a protocol-fatal error — it should be treated as a failed verification, not an unrecoverable error.

Concretely, in `dlogeq::verify`, replace the `?` on `encode_two_points` with a match that maps `Err(IdentityElement)` to `Ok(false)`.

---

### Proof of Concept

```rust
// Attacker knows generator1 = big_f.eval_at_zero() from round 2
// Attacker freely picks s_mal and e_mal (nonzero scalars)
let s_mal = some_nonzero_scalar;
let e_mal = some_nonzero_scalar;

// Craft big_c_j so that generator1 * s_mal - big_c_j * e_mal = identity
// => big_c_j = generator1 * (s_mal * e_mal^{-1})
let big_c_j = generator1 * (s_mal * e_mal.invert().unwrap());

// Submit big_c_j and proof { e: e_mal, s: s_mal } in round 4.
// When honest parties call dlogeq::verify:
//   big_k1 = generator1 * s_mal - big_c_j * e_mal
//          = generator1 * s_mal - generator1 * s_mal
//          = identity
// encode_two_points(&big_k0, &big_k1) returns Err(IdentityElement)
// The ? in do_generation_many propagates this, aborting the protocol.

// Assert: verify returns Err, not Ok(false)
let result = dlogeq::verify(&mut transcript, statement_with_crafted_big_c_j, &proof_mal);
assert!(matches!(result, Err(ProtocolError::IdentityElement)));
```

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L151-152)
```rust
        let (my_commitment, my_randomizer) = commit(&mut rng, &(&big_e_i, &big_f_i, &big_l_i))
            .map_err(|_| ProtocolError::PointSerialization)?;
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

**File:** src/crypto/proofs/dlogeq.rs (L82-99)
```rust
fn encode_two_points<C: Ciphersuite>(
    point_1: &Element<C>,
    point_2: &Element<C>,
) -> Result<Vec<u8>, ProtocolError> {
    // Create a serialization of big_k
    let mut ser1 = C::Group::serialize(point_1)
        .map_err(|_| ProtocolError::IdentityElement)?
        .as_ref()
        .to_vec();

    let ser2 = C::Group::serialize(point_2)
        .map_err(|_| ProtocolError::IdentityElement)?
        .as_ref()
        .to_vec();

    ser1.extend_from_slice(b" and ");
    ser1.extend_from_slice(&ser2);
    Ok(ser1)
```

**File:** src/crypto/proofs/dlogeq.rs (L153-157)
```rust
    let (phi0, phi1) = statement.phi(&proof.s.0);
    let big_k0 = phi0 - *statement.public0 * proof.e.0;
    let big_k1 = phi1 - *statement.public1 * proof.e.0;

    let enc = encode_two_points::<C>(&big_k0, &big_k1)?;
```
