### Title
Missing Minimum Threshold Enforcement in FROST Signing Allows Single-Party Signature Creation - (`src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` — the shared validation gate for all FROST EdDSA and RedJubjub signing entry-points — enforces an upper bound on the threshold but **omits the lower-bound check (`threshold < 2`)** that every other protocol entry-point in the library enforces. A caller who passes `threshold = 1` to any FROST signing function bypasses the multi-party security requirement, allowing the coordinator alone to aggregate a valid threshold signature without the participation of any other party.

---

### Finding Description

Every other protocol entry-point in the library that accepts a `threshold` parameter enforces a minimum of 2:

- `assert_key_invariants` (`src/dkg.rs`, line 580): `if threshold < 2 { return Err(ThresholdTooSmall { threshold, min: 2 }) }`
- `validate_triple_inputs` (`src/ecdsa/ot_based_ecdsa/triples/generation.rs`, line 699): identical guard

`assert_sign_inputs` in `src/frost/mod.rs` is the single validation function called by all FROST signing entry-points (`sign_v1`, `sign_v2` in `src/frost/eddsa/sign.rs`, and their RedJubjub equivalents). It validates:

1. `participants.len() < 2` → error
2. `threshold.value() > participants.len()` → error (upper bound only)
3. coordinator membership

It **never checks** `threshold.value() < 2`. [1](#0-0) 

The `threshold` value accepted here is then forwarded into the signing future (e.g. `fut_wrapper_v1`, `fut_wrapper_v2`) to determine how many signature shares the coordinator must collect before calling `aggregate`. With `threshold = 1`, the coordinator needs only its own share, satisfying the collection loop, and can call `aggregate` unilaterally to produce a valid, verifiable FROST signature.

Compare with the DKG guard that is present everywhere else: [2](#0-1) 

And the triple-generation guard: [3](#0-2) 

The `ReconstructionLowerBound` type itself imposes no minimum — it is a plain `usize` wrapper with no invariant: [4](#0-3) 

---

### Impact Explanation

With `threshold = 1` accepted by `assert_sign_inputs`, the FROST coordinator collects only its own nonce commitment and signature share, then calls `aggregate`. The resulting signature is a fully valid FROST signature verifiable against the group public key produced during keygen. No other participant's secret material is involved. This constitutes **unauthorized creation of a valid threshold signature for attacker-chosen inputs** by a single malicious coordinator, directly violating the t-of-n security guarantee the library is designed to provide.

---

### Likelihood Explanation

The entry-point is a public library API. Any application that allows its coordinator role to be filled by an untrusted or compromised party, or that exposes the `threshold` parameter to external configuration, is directly exploitable. The missing check is a single-line omission inconsistent with every other validation function in the codebase, making accidental misconfiguration equally likely.

---

### Recommendation

Add the same lower-bound guard present in `assert_key_invariants` and `validate_triple_inputs` to `assert_sign_inputs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Apply the same fix to the `presign` function in `src/frost/mod.rs` (line 72), which also only checks the upper bound on `args.threshold`. [5](#0-4) 

---

### Proof of Concept

```
1. Run keygen with participants = [P1, P2, P3], threshold = 2.
   → Succeeds; each party holds a valid signing share.

2. Call sign_v1(
       participants = [P1, P2, P3],
       threshold    = 1,          // ← passes assert_sign_inputs unchecked
       me           = P1 (coordinator),
       coordinator  = P1,
       keygen_output = P1's share,
       message      = <attacker-chosen message>,
   )

3. assert_sign_inputs checks:
   - participants.len() (3) >= 2  ✓
   - threshold (1) <= participants.len() (3)  ✓
   - coordinator in participants  ✓
   → No error returned.

4. The signing future collects threshold=1 commitment (P1's own).
   Coordinator calls aggregate with only P1's share.
   → Returns a valid FROST signature over the attacker-chosen message.

5. Verify signature against the group public key → success.
   No other party participated or consented.
```

### Citations

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

**File:** src/frost/mod.rs (L120-159)
```rust
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
    let threshold = threshold.into();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
    Ok(participants)
```

**File:** src/dkg.rs (L579-582)
```rust
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-704)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
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
