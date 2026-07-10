### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing Allows Caller-Controlled Denial of Signing - (File: src/frost/mod.rs)

### Summary
`assert_sign_inputs` in `src/frost/mod.rs` validates that `threshold <= participants.len()` but never checks that `threshold >= 2`. The DKG entry point (`assert_key_invariants`) enforces this lower bound, but the FROST signing entry point does not. Any caller who supplies `threshold = 1` (or `0`) to `sign_v1`, `sign_v2` (EdDSA), or `sign` (RedJubjub) will pass all initialization guards, proceed into the live signing protocol, and cause it to produce an unusable or cryptographically invalid output, denying signing for all honest participants in that session.

### Finding Description
`assert_key_invariants` in `src/dkg.rs` explicitly rejects `threshold < 2`:

```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

The analogous guard in `assert_sign_inputs` — the shared validation helper called by every FROST signing entry point — only checks the upper bound:

```rust
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [2](#0-1) 

There is no corresponding lower-bound check. `threshold = 1` and `threshold = 0` both pass silently.

`assert_sign_inputs` is the sole validation gate for:
- `sign_v1` / `sign_v2` in `src/frost/eddsa/sign.rs` [3](#0-2) 
- `sign` in `src/frost/redjubjub/sign.rs` [4](#0-3) 

The same missing lower-bound check exists in the FROST `presign` entry point:

```rust
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// no threshold >= 2 check
``` [5](#0-4) 

When `threshold = 1` reaches `construct_key_package`, it is converted to `u16` and forwarded to `frost_ed25519::KeyPackage::new` / `reddsa::frost::redjubjub::KeyPackage::new` as `min_signers = 1`. [6](#0-5) 

With `min_signers = 1`, the FROST aggregate step requires only one signature share (the coordinator's own), computes Lagrange coefficients over a single-element set, and produces a scalar that does not reconstruct the group secret. The resulting signature fails the internal `aggregate` verification, causing the protocol to abort with an error for all participants.

### Impact Explanation
A caller who controls the `threshold` argument — including a malicious coordinator who drives the signing session — can pass `threshold = 1` to any FROST signing call. All participants will execute the full signing round, exchange nonces and signature shares, and then receive a protocol error when the coordinator's `aggregate` call fails. No valid signature is produced. Because the same coordinator can repeat this on every signing attempt, honest parties are permanently denied the ability to produce a threshold signature under that coordinator, matching the **High: Permanent denial of signing for honest parties** impact class.

### Likelihood Explanation
Low. The caller must deliberately (or accidentally) supply a threshold value below 2. In a well-integrated deployment the threshold is read from the DKG output and passed through unchanged, so accidental misuse is unlikely. However, a malicious or compromised coordinator who constructs the signing call can trivially trigger this by passing `threshold = 1` without any other privilege escalation.

### Recommendation
Add the same lower-bound guard that `assert_key_invariants` already enforces to `assert_sign_inputs` and to the `presign` entry point in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Place this check immediately after converting the `threshold` argument, before any participant-list construction, mirroring the pattern in `assert_key_invariants`. [1](#0-0) 

### Proof of Concept
1. Run DKG for 3 participants with `threshold = 2` (accepted, because `assert_key_invariants` enforces `>= 2`).
2. Call `sign_v1` with the same 3 participants but `threshold = 1`.
3. `assert_sign_inputs` checks `1 > 3` → false; no error is returned. [2](#0-1) 
4. `construct_key_package` converts `threshold = 1` to `u16` and creates a `KeyPackage` with `min_signers = 1`. [6](#0-5) 
5. The coordinator aggregates using only its own signature share; Lagrange interpolation over a single point does not reconstruct the group secret.
6. `aggregate` fails internal signature verification; the protocol returns `ProtocolError::AssertionFailed`.
7. No valid signature is produced; all honest participants' signing work is wasted and the session must be abandoned.

### Citations

**File:** src/dkg.rs (L580-582)
```rust
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/frost/mod.rs (L72-77)
```rust
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
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

**File:** src/frost/eddsa/sign.rs (L46-48)
```rust
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

```

**File:** src/frost/redjubjub/sign.rs (L49-50)
```rust
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
```

**File:** src/frost/redjubjub/sign.rs (L254-257)
```rust
        u16::try_from(threshold.value()).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    );
```
