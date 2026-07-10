### Title
Undocumented `u16` Truncation of `ReconstructionLowerBound` Causes Permanent Denial of FROST Signing for Valid Threshold Values - (File: `src/frost/eddsa/sign.rs`, `src/frost/redjubjub/sign.rs`)

---

### Summary

The FROST EdDSA and RedJubjub signing paths silently impose an undocumented upper bound of 65535 on the threshold parameter by casting `ReconstructionLowerBound` (a `usize`) to `u16` inside `construct_key_package`. The initialization guard `assert_sign_inputs` does not enforce this limit, so any caller who legitimately configures a threshold above 65535 passes all pre-flight checks but then receives a mid-protocol `ProtocolError` during every signing attempt, permanently denying signing for all honest parties in that session.

---

### Finding Description

`ReconstructionLowerBound` wraps a `usize` with no documented ceiling. The public entry-point validation in `assert_sign_inputs` (`src/frost/mod.rs`) only checks that `threshold <= participants.len()` and `threshold >= 2`; it imposes no upper bound.

Inside the signing execution path, both FROST variants call `construct_key_package`, which converts the threshold to `u16` for the underlying `frost_core::KeyPackage`:

**`src/frost/eddsa/sign.rs` lines 360–368:**
```rust
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

**`src/frost/redjubjub/sign.rs` lines 249–257:**
```rust
let key_package = KeyPackage::new(
    identifier,
    signing_share,
    verifying_share,
    verifying_key,
    u16::try_from(threshold.value()).map_err(|_| {
        ProtocolError::Other("threshold cannot be converted to u16".to_string())
    })?,
);
```

If `threshold.value() > 65535`, `u16::try_from` returns `Err`, the `?` propagates a `ProtocolError::Other`, and the signing future terminates. Because this happens inside the async execution body (not at initialization), all participants have already committed to the session before the failure is discovered. Every subsequent signing attempt with the same configuration will fail identically.

The initialization path (`assert_sign_inputs`, `src/frost/mod.rs` lines 120–159) has no corresponding guard:

```rust
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
```

There is no `if threshold.value() > u16::MAX` check anywhere in the initialization or validation chain.

---

### Impact Explanation

Any honest party set that legitimately configures a FROST EdDSA or RedJubjub signing session with `threshold > 65535` will find that:

1. `sign_v1`, `sign_v2` (EdDSA), and `sign` (RedJubjub) all succeed at initialization.
2. Every execution of the signing protocol terminates with `ProtocolError::Other("threshold cannot be converted to u16")` before any signature share is produced.
3. No valid threshold signature can ever be produced for that key configuration.

This is **permanent denial of signing for honest parties under valid protocol inputs**, matching the High impact category.

---

### Likelihood Explanation

Having more than 65535 participants is computationally infeasible for any real threshold signature deployment. The library itself notes that "you won't actually be able to make the protocols work with billions of users." The likelihood of a real-world deployment hitting this limit is very low. However, the root cause is a real, reachable code path with no documentation of the restriction, and the initialization API accepts the invalid configuration without error, making the failure non-obvious to library consumers.

---

### Recommendation

Add an explicit upper-bound check in `assert_sign_inputs` (and in the EdDSA/RedJubjub presign entry points) before the protocol is started:

```rust
if threshold.value() > usize::from(u16::MAX) {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: usize::from(u16::MAX),
    });
}
```

Alternatively, document the `u16::MAX` ceiling on `ReconstructionLowerBound` in the public API and enforce it at the type level or in `ReconstructionLowerBound::new`.

---

### Proof of Concept

```rust
// Both sign_v1 and sign_v2 accept this at initialization:
let threshold: usize = 65536; // > u16::MAX
let participants = generate_participants(65537);
let result = sign_v1(&participants, threshold, me, coordinator, keygen_output, msg, rng);
// result is Ok(...) — initialization succeeds

// But when the protocol executes, construct_key_package is called:
// u16::try_from(65536_usize) → Err(_)
// → ProtocolError::Other("threshold cannot be converted to u16")
// Every participant's signing future terminates; no signature is ever produced.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/frost/eddsa/sign.rs (L360-368)
```rust
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

**File:** src/frost/redjubjub/sign.rs (L249-257)
```rust
    let key_package = KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        verifying_key,
        u16::try_from(threshold.value()).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    );
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

**File:** src/thresholds.rs (L9-24)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);

// ----- MaxMalicious conversions -----
impl MaxMalicious {
    pub fn value(self) -> usize {
        self.0
    }
}

impl ReconstructionLowerBound {
    pub fn value(self) -> usize {
        self.0
    }
```
