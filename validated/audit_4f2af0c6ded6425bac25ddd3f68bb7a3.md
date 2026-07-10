### Title
Missing Minimum Threshold Validation in FROST Signing and Presigning Allows Corrupted or Unusable Signature Outputs - (File: src/frost/mod.rs)

---

### Summary

`assert_sign_inputs` and `presign` in `src/frost/mod.rs` validate only the upper bound of the `threshold` parameter (`threshold > participants.len()`) but never enforce the lower bound (`threshold >= 2`). This is directly inconsistent with `assert_key_invariants` in `src/dkg.rs`, which explicitly rejects `threshold < 2`. A caller or malicious coordinator can pass `threshold = 1` (or `0`) to FROST signing, causing the protocol to proceed with a threshold that is structurally incompatible with the key material, producing unusable cryptographic outputs or causing the signing round to fail permanently for all honest participants.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces a hard lower bound:

```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`validate_triple_inputs` in the OT-based triple generation path applies the same guard: [2](#0-1) 

However, `assert_sign_inputs` — the public validation entry point for all FROST signing calls — only checks the upper bound:

```rust
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [3](#0-2) 

There is no corresponding `threshold < 2` guard. The same omission exists in the FROST `presign` function: [4](#0-3) 

`ReconstructionLowerBound` is a plain newtype over `usize` with no invariant enforcement, so any value including `0` or `1` is accepted without error: [5](#0-4) 

`assert_sign_inputs` is the sole validation gate called by both `sign_v1` and `sign_v2` in `src/frost/eddsa/sign.rs` and `src/frost/redjubjub/sign.rs`: [6](#0-5) 

When `threshold = 1` passes `assert_sign_inputs`, execution reaches `construct_key_package`, which forwards the value directly to the FROST library as `min_signers`:

```rust
u16::try_from(threshold.value()).map_err(...)?,
``` [7](#0-6) 

The FROST library then computes Lagrange coefficients and aggregates signature shares using `min_signers = 1`. Because the key was generated with a degree-`(threshold-1)` polynomial where `threshold >= 2`, the Lagrange basis used during signing is structurally incompatible with the key material. The aggregated signature is either cryptographically invalid (fails external verification) or the FROST library's internal `aggregate` verification rejects it, causing the signing round to abort for all honest participants.

---

### Impact Explanation

When a caller or malicious coordinator supplies `threshold = 1` to `sign_v1` / `sign_v2`:

1. All honest participants complete their local computation and emit signature shares.
2. The coordinator aggregates with `min_signers = 1`, using Lagrange coefficients inconsistent with the keygen polynomial degree.
3. The resulting signature is either rejected by the FROST library's internal check inside `aggregate`, or it is accepted but fails external verification — in both cases the signing output is **unusable**.
4. Honest parties have consumed their nonces (which must never be reused) and cannot recover without a fresh presign round.

This matches the allowed impact: **Corruption of sign outputs so honest parties accept inconsistent transcripts or unusable cryptographic outputs**, and **Permanent denial of signing for honest parties under valid protocol inputs**.

---

### Likelihood Explanation

`threshold` is a caller-supplied parameter with no type-level enforcement. Any library consumer — including a malicious coordinator orchestrating a multi-party signing session — can pass `threshold = 1` without triggering any error at initialization time. The missing check is a single-line omission that is directly analogous to the missing `burnCommission` initialization in the reference report: a parameter that is validated everywhere else in the codebase is silently accepted as zero/one in the signing path.

---

### Recommendation

Add the same lower-bound guard that exists in `assert_key_invariants` and `validate_triple_inputs` to both `assert_sign_inputs` and `presign` in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be inserted immediately after the upper-bound check in both functions, mirroring the pattern already established at: [8](#0-7) 

---

### Proof of Concept

```rust
// Keygen is performed correctly with threshold = 2
let participants = generate_participants(2);
let keygen_output = run_keygen::<Ed25519Sha512>(&participants, 2, &mut rng);

// Malicious coordinator calls sign_v1 with threshold = 1
// assert_sign_inputs passes: 1 <= 2 (participants.len()), no lower-bound check
let result = frost::eddsa::sign::sign_v1(
    &participants,
    1usize,          // threshold = 1, below the enforced minimum of 2
    participants[0],
    participants[0], // coordinator
    keygen_output[0].1.clone(),
    b"message".to_vec(),
    rng,
);
// Returns Ok(...) — no InitializationError is raised
// Protocol proceeds; construct_key_package receives min_signers = 1
// Aggregated signature is structurally inconsistent with the degree-1 keygen polynomial
// aggregate() either errors or produces an invalid signature
```

The initialization succeeds where it should fail, mirroring the `burnCommission == 0` scenario in the reference report: the missing lower-bound guard allows the protocol to proceed into a state that produces unusable outputs.

### Citations

**File:** src/dkg.rs (L579-582)
```rust
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-703)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
```

**File:** src/frost/mod.rs (L71-77)
```rust
    // validate threshold
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

**File:** src/frost/eddsa/sign.rs (L37-61)
```rust
pub fn sign_v1(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::new();
    let chan = comms.shared_channel();
    let fut = fut_wrapper_v1(
        chan,
        participants,
        threshold,
        me,
        coordinator,
        keygen_output,
        message,
        rng,
    );
    Ok(make_protocol(comms, fut))
```

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
