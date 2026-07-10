### Title
Wrong Lagrange Coefficient Base Set in Reshare Linearization Causes Permanent Resharing Denial - (File: src/dkg.rs)

### Summary
In `do_reshare`, the Lagrange coefficient used to linearize each old participant's share is computed over the **intersection** of old and new participants, rather than over the **old participants** set. When old participants are being rotated out (a standard resharing use case), the intersection is a strict subset of the old participants, producing incorrect Lagrange coefficients. The resulting linearized shares do not reconstruct the original secret, the new public key diverges from the old one, and the protocol permanently aborts for all honest parties.

### Finding Description

In `src/dkg.rs`, `do_reshare` computes:

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection          // ← wrong base set
            .lagrange::<C>(me)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    ...
``` [1](#0-0) 

The Lagrange coefficient `λ_i` is defined relative to a specific evaluation domain. For resharing to be correct, each old participant `i` must compute `λ_i(old_participants) · x_i`, so that the sum across all old participants reconstructs the original secret `s`:

```
Σ_i  λ_i(old_participants) · x_i  =  s
```

When the base set is `intersection` instead of `old_participants`, the coefficients change:

```
λ_i(intersection)  ≠  λ_i(old_participants)   (when intersection ⊊ old_participants)
```

and the sum no longer equals `s`. Every old participant in the intersection computes a wrong linearized share, so the combined polynomial committed during `do_keyshare` encodes a different secret.

The mismatch is caught by the public-key consistency check in `do_keyshare`:

```rust
if old_vk != verifying_key {
    return Err(ProtocolError::AssertionFailed(
        "new public key does not match old public key".to_string(),
    ));
}
``` [2](#0-1) 

This causes the resharing to abort deterministically for every honest participant.

The precondition check in `assert_reshare_keys_invariants` explicitly permits the intersection to be a strict subset of `old_participants` (it only requires `intersection.len() >= old_threshold`), confirming this scenario is within the documented trust model:

```rust
if old_participants.intersection(&participants).len() < old_threshold {
    return Err(...);
}
``` [3](#0-2) 

### Impact Explanation

Any resharing where at least one old participant is not in the new participant set triggers the bug. The protocol aborts with a hard error at every honest node. No new key shares are produced. The existing key material remains valid but the resharing operation — including participant rotation and threshold changes — is permanently unavailable for any such configuration. This matches the allowed High impact: **Permanent denial of reshare for honest parties under valid protocol inputs and documented trust assumptions**.

### Likelihood Explanation

Rotating out old participants is the primary motivation for resharing. The API accepts and validates such inputs without error (the intersection-size check passes). Any caller performing a standard participant rotation will hit this bug on every attempt. Likelihood is **High**.

### Recommendation

Replace `intersection` with `old_participants` when computing the Lagrange coefficient:

```rust
// Before (wrong):
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection.lagrange::<C>(me)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    ...

// After (correct):
let secret = old_signing_key
    .map(|x_i| {
        old_participants.lagrange::<C>(me)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    ...
```

The `intersection` variable is still needed for the `assert_keyshare_inputs` check (to determine whether `me` is a purely new joiner), but it must not be used as the Lagrange evaluation domain for share linearization.

### Proof of Concept

Consider a 2-of-3 resharing where old participants are `{P1, P2, P3}` and new participants are `{P2, P3, P4}` (P1 is rotated out, P4 is added). The intersection is `{P2, P3}`.

- **Correct**: P2 and P3 each compute `λ_i({P1,P2,P3}) · x_i`. The sum reconstructs `s`.
- **Actual**: P2 and P3 each compute `λ_i({P2,P3}) · x_i`. These are 2-point Lagrange coefficients, not 3-point ones. The sum equals a different value `s' ≠ s`.

The new public key derived from `s'` differs from the old one. `do_keyshare` detects this at line 491 and returns `ProtocolError::AssertionFailed("new public key does not match old public key")` for every participant, permanently blocking the reshare. [4](#0-3)

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

**File:** src/dkg.rs (L611-635)
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

    let old_reshare_package = Some((old_public_key, old_participants));
    let keygen_output = do_keyshare::<C>(
        chan,
        participants,
        me,
        threshold,
        secret,
        old_reshare_package,
        &mut rng,
    )
    .await?;

    Ok(keygen_output)
}
```

**File:** src/dkg.rs (L655-660)
```rust
    if old_participants.intersection(&participants).len() < old_threshold {
        return Err(InitializationError::NotEnoughParticipantsForNewThreshold {
            threshold: old_threshold,
            participants: old_participants.intersection(&participants).len(),
        });
    }
```
