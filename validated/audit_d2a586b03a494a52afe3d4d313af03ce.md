### Title
Wrong Condition Check in `assert_reshare_keys_invariants` Allows Malicious New Participant to Corrupt Reshare Output — (`File: src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` contains a wrong condition check at line 663. The inline comment explicitly states the intended guard — *"if me is not in the old participant set then ensure that old_signing_key is None"* — but the code implements the **opposite** predicate. The intended check (new participant supplying a key → reject) is entirely absent. A malicious new participant can therefore pass a fabricated `old_signing_key` through validation unchallenged, causing `do_reshare` to inject a non-zero, attacker-controlled secret contribution into the reshare protocol, which corrupts the reshare output and forces all honest parties into a failed protocol run.

---

### Finding Description

The guard at `src/dkg.rs` line 663 reads:

```rust
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
```

The comment describes the check that **should** be present:

> "if `me` is **not** in the old participant set → `old_signing_key` must be `None`"

Translated to code, the intended guard is:

```rust
if !old_participants.contains(me) && old_signing_key.is_some() { … }
```

The implemented guard is the **orthogonal** condition:

```rust
if old_participants.contains(me) && old_signing_key.is_none() { … }
```

These two predicates are logically independent. The code correctly rejects an *old* participant who omits their share, but it **never rejects** a *new* participant who supplies a share. The comment's intended invariant is therefore completely unenforced. [1](#0-0) 

Downstream, `do_reshare` computes the new participant's secret contribution as:

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?
    .unwrap_or_else(<C::Group as Group>::Field::zero);
``` [2](#0-1) 

When `me` is **not** in `old_participants`, `me` is absent from `intersection`. The call `intersection.lagrange::<C>(me)` evaluates the Lagrange basis polynomial for a point outside the interpolation set, producing a non-trivial (non-zero) scalar. The `lagrange` function does not check whether `p` is a member of `self`; it simply evaluates the polynomial:

```rust
pub fn lagrange<C: Ciphersuite>(&self, p: Participant) -> Result<Scalar<C>, ProtocolError> {
    let p = p.scalar::<C>();
    let identifiers: Vec<Scalar<C>> = self.participants().iter()
        .map(Participant::scalar::<C>).collect();
    Ok(compute_lagrange_coefficient::<C>(&identifiers, &p, None)?.0)
}
``` [3](#0-2) 

The result is `secret = λ · x_i` where `λ` is a non-zero Lagrange coefficient and `x_i` is the attacker-supplied fake key. This non-zero secret becomes the constant term of the new participant's secret polynomial, so every share they distribute to other participants is wrong. The reshare then fails at the public-key consistency check inside `do_keyshare`:

```rust
if let Some(old_vk) = old_verification_key {
    if old_vk != verifying_key {
        return Err(ProtocolError::AssertionFailed(
            "new public key does not match old public key".to_string(),
        ));
    }
}
``` [4](#0-3) 

Every honest participant independently performs this check and aborts, making the reshare output **unusable** for all parties.

---

### Impact Explanation

A single malicious new participant (one not present in `old_participants`) can supply any non-`None` `old_signing_key`. Validation passes silently because the wrong condition is checked. The participant then injects an attacker-controlled, non-zero scalar into the reshare's secret reconstruction, producing a corrupted aggregate secret whose corresponding public key differs from the original. All honest parties detect the mismatch and abort, yielding an unusable reshare output.

This maps to: **High — Corruption of reshare outputs so honest parties accept inconsistent public keys or unusable cryptographic outputs.**

---

### Likelihood Explanation

The entry point is the public `assert_reshare

### Citations

**File:** src/dkg.rs (L489-496)
```rust
    if let Some(old_vk) = old_verification_key {
        // check the equality between the old key and the new key without failing the unwrap
        if old_vk != verifying_key {
            return Err(ProtocolError::AssertionFailed(
                "new public key does not match old public key".to_string(),
            ));
        }
    }
```

**File:** src/dkg.rs (L611-621)
```rust
    let intersection = old_participants.intersection(&participants);
    // either extract the share and linearize it or set it to zero
    let secret = old_signing_key
        .map(|x_i| {
            intersection
                .lagrange::<C>(me)
                .map(|lambda| lambda * x_i.to_scalar())
        })
        .transpose()?
        .unwrap_or_else(<C::Group as Group>::Field::zero);

```

**File:** src/dkg.rs (L661-667)
```rust
    // Step 1.1
    // if me is not in the old participant set then ensure that old_signing_key is None
    if old_participants.contains(me) && old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "party {me:?} is present in the old participant list but provided no share"
        )));
    }
```

**File:** src/participants.rs (L151-159)
```rust
    pub fn lagrange<C: Ciphersuite>(&self, p: Participant) -> Result<Scalar<C>, ProtocolError> {
        let p = p.scalar::<C>();
        let identifiers: Vec<Scalar<C>> = self
            .participants()
            .iter()
            .map(Participant::scalar::<C>)
            .collect();
        Ok(compute_lagrange_coefficient::<C>(&identifiers, &p, None)?.0)
    }
```
