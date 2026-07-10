### Title
Missing Lower-Bound Threshold Validation in FROST Signing Enables Invalid Signing State — (File: `src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` validates that the threshold does not exceed the participant count but omits the symmetric lower-bound check (`threshold >= 2`) that is enforced during key generation in `assert_key_invariants`. A malicious coordinator or any API caller can supply `threshold = 1` to `sign_v1`, `sign_v2`, or `redjubjub::sign`, causing the FROST `KeyPackage` to be constructed with `min_signers = 1`. Honest participants then execute a signing session whose threshold invariant is inconsistent with the one established at keygen time, producing unusable cryptographic output.

---

### Finding Description

`assert_key_invariants` (`src/dkg.rs`, lines 573–582) enforces **both** bounds on the threshold:

```rust
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

`assert_sign_inputs` (`src/frost/mod.rs`, lines 144–150) enforces **only the upper bound**:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← lower-bound check is absent
```

Both `sign_v1` and `sign_v2` in `src/frost/eddsa/sign.rs` (lines 47, 73) and `sign` in `src/frost/redjubjub/sign.rs` (line 50) delegate exclusively to `assert_sign_inputs` for threshold validation. With `threshold = 1` silently accepted, `construct_key_package` (`src/frost/eddsa/sign.rs`, lines 360–368) creates a `KeyPackage` with `min_signers = 1`:

```rust
Ok(KeyPackage::new(
    identifier,
    signing_share,
    verifying_share,
    *verifying_key,
    u16::try_from(threshold.