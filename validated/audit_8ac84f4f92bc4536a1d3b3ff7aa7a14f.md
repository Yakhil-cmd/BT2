### Title
Missing `ThresholdTooSmall` Check in FROST Signing Validation Allows Threshold Bypass - (File: `src/frost/mod.rs`)

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` validates the threshold upper bound (`threshold > participants.len()`) but omits the lower-bound check (`threshold < 2`) that is enforced in every other validation function in the codebase. A malicious coordinator or library caller can invoke `sign_v1`, `sign_v2`, or `redjubjub::sign` with `threshold = 1`, causing the FROST `KeyPackage` to be constructed with a minimum-signer count of 1 and allowing a single participant to produce a valid threshold signature without the required quorum.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on the threshold:

```rust
// Step 1.1
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// Step 1.1
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`validate_triple_inputs` in the OT-based ECDSA triple generation also enforces both bounds:

```rust
if threshold_value > participants.len() { ... }
if threshold_value < 2 { ... }
``` [2](#0-1) 

However, `assert_sign_inputs` in `src/frost/mod.rs` — the shared validation function called by all FROST signing entry points — only checks the upper bound:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← NO ThresholdTooSmall check here
``` [3](#0-2) 

This function is the sole gate for all three FROST signing entry points:

- `frost::eddsa::sign::sign_v1` and `sign_v2` — both call `assert_sign_inputs` and nothing else for threshold validation. [4](#0-3) [5](#0-4) 

- `frost::redjubjub::sign::sign` — also delegates entirely to `assert_sign_inputs`. [6](#0-5) 

After `assert_sign_inputs` passes, the threshold is forwarded directly into `construct_key_package`, which embeds it as the FROST `KeyPackage` minimum-signer count:

```rust
Ok(KeyPackage::new(
    identifier,
    signing_share,
    verifying_share,
    *verifying_key,
    u16::try_from(threshold.value())...,
))
``` [7](#0-6) 

FROST's `aggregate` function uses the threshold embedded in the `KeyPackage` to determine how many valid signature shares are required. With `threshold = 1`, only one share is needed for aggregation to succeed.

---

### Impact Explanation

**Critical — Unauthorized creation of a valid threshold signature.**

A caller who passes `threshold = 1` to any FROST signing function bypasses the quorum requirement established at key-generation time. The FROST `KeyPackage` is constructed with a minimum-signer count of 1, so the coordinator's own single signature share is sufficient for `aggregate` to produce a valid, verifiable signature over the group's public key. This completely undermines the threshold security property: a single party (the coordinator) can sign arbitrary messages without the participation of any other key-share holder.

---

### Likelihood Explanation

The signing functions are public API entry points. Any library caller — including a malicious coordinator — can supply an arbitrary `threshold` value. There is no out-of-band enforcement; the only guard is `assert_sign_inputs`, which is missing the lower-bound check. The attack requires no cryptographic capability, no leaked keys, and no external dependency failure — only the ability to call the public `sign` function with a crafted argument.

---

### Recommendation

Add the missing lower-bound check to `assert_sign_inputs` in `src/frost/mod.rs`, mirroring the check already present in `assert_key_invariants`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be inserted alongside the existing upper-bound check at lines 144–150 of `src/frost/mod.rs`.

---

### Proof of Concept

1. Run DKG with 3 participants and `threshold = 3` (all three must sign).
2. Call `frost::eddsa::sign::sign_v1` with the same 3 participants but `threshold = 1`.
3. `assert_sign_inputs` accepts `threshold = 1` because `1 <= 3` (upper-bound check passes, lower-bound check absent). [3](#0-2) 
4. `construct_key_package` embeds `threshold = 1` into the FROST `KeyPackage`. [8](#0-7) 
5. The coordinator computes its own signature share and calls `aggregate`. With `threshold = 1` in the `KeyPackage`, FROST accepts the single share and returns a valid signature.
6. The resulting signature verifies against the group public key that was generated with `threshold = 3`, meaning the coordinator has produced a valid threshold signature without the participation of the other two key-share holders.

### Citations

**File:** src/dkg.rs (L572-582)
```rust
    // validate threshold
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L693-704)
```rust
    if threshold_value > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold_value,
            max: participants.len(),
        });
    }
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
```

**File:** src/frost/mod.rs (L144-150)
```rust
    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }
```

**File:** src/frost/eddsa/sign.rs (L46-47)
```rust
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
```

**File:** src/frost/eddsa/sign.rs (L73-73)
```rust
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
```

**File:** src/frost/eddsa/sign.rs (L351-368)
```rust
fn construct_key_package(
    threshold: ReconstructionLowerBound,
    me: Participant,
    signing_share: SigningShare,
    verifying_key: &VerifyingKey,
) -> Result<KeyPackage, ProtocolError> {
    let identifier = me.to_identifier()?;
    let verifying_share = signing_share.into();

    Ok(KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        *verifying_key,
        u16::try_from(threshold.value()).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    ))
```

**File:** src/frost/redjubjub/sign.rs (L49-50)
```rust
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
```
