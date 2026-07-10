### Title
`PresignOutput` and `RerandomizedPresignOutput` Derive `Clone` with No Use-Once Enforcement, Enabling Presignature Nonce Reuse and Private Key Extraction - (File: src/ecdsa/robust_ecdsa/mod.rs)

---

### Summary

Both the robust and OT-based ECDSA presignature output types derive `Clone` and `Serialize`/`Deserialize`, providing no type-level enforcement of the documented one-time-use requirement. A malicious coordinator can clone presignature material and orchestrate two signing sessions against the same underlying nonce `R` with different messages, producing multiplicatively related nonces from which the aggregate private key can be algebraically recovered.

---

### Finding Description

The security documentation is explicit:

> *"Never reuse a presignature, even across failed, aborted, or partially completed signing sessions."*
> *"If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks."*

Despite this, both presignature output types derive `Clone`:

**Robust ECDSA** — `src/ecdsa/robust_ecdsa/mod.rs`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput { ... }
```

**OT-based ECDSA** — `src/ecdsa/ot_based_ecdsa/mod.rs`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput { ... }
```

The `sign()` function in `src/ecdsa/robust_ecdsa/sign.rs` takes `presignature: RerandomizedPresignOutput` **by value** (move semantics), which would enforce one-time use at the type level — but only if `Clone` were absent. Since both `PresignOutput` and `RerandomizedPresignOutput` derive `Clone`, a caller trivially clones the struct before passing it, bypassing the move-based protection entirely.

This is confirmed as a real usage pattern: `benches/bench_utils.rs` explicitly calls `.clone()` on `RerandomizedPresignOutput` at lines 248 and 370 after the signing protocol has already consumed it, demonstrating the pattern is exercised in the codebase.

The rerandomization function `RerandomizedPresignOutput::rerandomize_presign` in `src/ecdsa/robust_ecdsa/mod.rs` (lines 54–86) takes `presignature: &PresignOutput` (shared reference), so a caller can rerandomize the same `PresignOutput` multiple times with different `RerandomizationArguments` (different `h`, `ε`, `ρ`), producing:

- `R1 = delta1 · R` (from HKDF over h1, ε, ρ, R)
- `R2 = delta2 · R` (from HKDF over h2, ε, ρ, R)

Both `delta1` and `delta2` are known to the coordinator (they supply the `RerandomizationArguments`). The resulting nonces are multiplicatively related: `R1 = (delta1/delta2) · R2`.

In the robust ECDSA signing protocol (`src/ecdsa/robust_ecdsa/sign.rs` lines 110–124), each participant sends their individual signature share `s_i` **only to the coordinator**. The coordinator therefore collects per-participant shares across both sessions:

- Session 1: `s1_i = alpha1_i · h1 + beta1_i · R1_x + e_i`
- Session 2: `s2_i = alpha2_i · h2 + beta2_i · R2_x + e_i`

Since the coordinator knows `delta1`, `delta2`, `R1_x`, `R2_x`, `h1`, `h2`, and the per-participant shares, the system of equations is solvable for the secret shares `alpha_i`, `beta_i`, `e_i`. With those recovered, the aggregate private key `x` follows from standard ECDSA nonce-reuse algebra:

```
x = (s2·h1 - s1·c·h2) / (s1·c·r2 - s2·r1)
where c = delta1 / delta2
```

Participants have no mechanism to detect or refuse a second signing request using the same presignature — there is no use-once tracking on their side either.

---

### Impact Explanation

**Critical — Extraction of the aggregate private signing key.**

A malicious coordinator who controls the `RerandomizationArguments` for two signing sessions derived from the same `PresignOutput` can recover the full private key. This enables the coordinator to forge valid ECDSA signatures for any message under the threshold key, without participation from any honest party.

This matches the allowed impact: *"Critical: Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets."*

---

### Likelihood Explanation

**Medium.** The coordinator is a designated role in the signing protocol, reachable by any participant without privileged assumptions. The attack requires only two signing sessions using the same presignature — a realistic scenario in any system that pre-generates presignatures in bulk and allows the coordinator to select which presignature to use for each signing request. The `Clone` derive makes the reuse trivial to implement; no cryptographic capability is required.

---

### Recommendation

1. **Remove `Clone` from `PresignOutput` and `RerandomizedPresignOutput`** in both `src/ecdsa/robust_ecdsa/mod.rs` and `src/ecdsa/ot_based_ecdsa/mod.rs`. The by-value consumption in `sign()` already provides the correct Rust idiom for enforcing one-time use — `Clone` silently defeats it.

2. If serialization for storage is required, use a newtype wrapper with explicit documentation that deserialization reconstitutes a one-time-use value, and audit all deserialization call sites.

3. Participants should maintain a local set of consumed presignature identifiers (e.g., keyed by `big_r`) and refuse to sign if the same presignature nonce is presented a second time.

---

### Proof of Concept

```rust
// 1. Run presigning — all participants produce their PresignOutput
let presign_outputs: Vec<(Participant, PresignOutput)> = run_presign(...);

// 2. Malicious coordinator clones the PresignOutput before consuming it
let presign_clone: Vec<(Participant, PresignOutput)> = presign_outputs
    .iter()
    .map(|(p, out)| (*p, out.clone()))   // Clone derives make this trivial
    .collect();

// 3. Rerandomize with message h1 → R1 = delta1 * R
let rerand_args_1 = RerandomizationArguments::new(pk, tweak, h1_bytes, big_r, ...);
let session1: Vec<(Participant, RerandomizedPresignOutput)> = presign_outputs
    .iter()
    .map(|(p, out)| (*p, RerandomizedPresignOutput::rerandomize_presign(out, &rerand_args_1).unwrap()))
    .collect();

// 4. Rerandomize the clone with message h2 → R2 = delta2 * R (same underlying R)
let rerand_args_2 = RerandomizationArguments::new(pk, tweak, h2_bytes, big_r, ...);
let session2: Vec<(Participant, RerandomizedPresignOutput)> = presign_clone
    .iter()
    .map(|(p, out)| (*p, RerandomizedPresignOutput::rerandomize_presign(out, &rerand_args_2).unwrap()))
    .collect();

// 5. Run both signing sessions — coordinator collects per-participant shares s1_i and s2_i
// 6. Coordinator computes c = delta1 / delta2 (both known)
// 7. Recover private key: x = (s2*h1 - s1*c*h2) / (s1*c*r2 - s2*r1)
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** src/ecdsa/robust_ecdsa/mod.rs (L26-37)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize(skip)]
    pub big_r: AffinePoint,

    /// Our secret shares of the nonces.
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}
```

**File:** src/ecdsa/robust_ecdsa/mod.rs (L42-52)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    #[zeroize(skip)]
    big_r: AffinePoint,

    /// Our rerandomized secret shares of the nonces.
    e: Scalar,
    alpha: Scalar,
    beta: Scalar,
}
```

**File:** src/ecdsa/robust_ecdsa/mod.rs (L54-86)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
        }
        let delta = args.derive_randomness()?;
        if delta.is_zero().into() {
            return Err(ProtocolError::ZeroScalar);
        }

        // cannot be zero due to the previous check
        let inv_delta = delta.invert().unwrap();

        // delta * R
        let rerandomized_big_r = presignature.big_r * delta;

        // alpha * delta^{-1}
        let rerandomized_alpha = presignature.alpha * inv_delta;

        // (beta + c*tweak) * delta^{-1}
        let rerandomized_beta =
            (presignature.beta + presignature.c * args.tweak.value()) * inv_delta;

        Ok(Self {
            big_r: rerandomized_big_r.into(),
            alpha: rerandomized_alpha,
            beta: rerandomized_beta,
            e: presignature.e,
        })
    }
```

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L40-63)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our share of the nonce value.
    pub k: Scalar,
    /// Our share of the sigma value.
    pub sigma: Scalar,
}

/// The output of the presigning protocol.
/// Contains the signature precomputed elements
/// independently of the message
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our rerandomized share of the nonce value.
    pub k: Scalar,
    /// Our rerandomized share of the sigma value.
    pub sigma: Scalar,
}
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L33-108)
```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: impl Into<MaxMalicious>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    // ensure number of participants during the signing phase is >= 2 * max_malicious + 1
    let robust_ecdsa_threshold = max_malicious
        .into()
        .value()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            InitializationError::BadParameters(
                "2*threshold+1 must be less than usize::MAX".to_string(),
            )
        })?;
    if robust_ecdsa_threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "2*max_malicious+1 must be less than or equals to participant count".to_string(),
        ));
    }

    // The next two conditions prevent split-view attacks
    // documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during signing must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }

    let ctx = Comms::new();
    let fut = fut_wrapper(
        ctx.shared_channel(),
        participants,
        coordinator,
        me,
        public_key,
        presignature,
        msg_hash,
    );
    Ok(make_protocol(ctx, fut))
}
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L151-158)
```markdown
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.

Moreover, due to protocol modifications relative to [[DJNPO20](https://eprint.iacr.org/2020/501)] (notably signature-share
linearization), **a novel split-view attack exists that can extract the secret key using as
few as $2t + 2$ presigning participants**, with as few as two signing sessions.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-177)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.
```

**File:** benches/bench_utils.rs (L245-251)
```rust
    OTECDSAPreparedSig {
        protocols,
        index,
        presig: result[index].1.clone(),
        derived_pk,
        msg_hash,
    }
```
