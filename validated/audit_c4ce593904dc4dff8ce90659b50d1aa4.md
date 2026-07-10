### Title
Missing Single-Use Enforcement on `PresignOutput` Enables Presignature Reuse and Private Key Extraction - (File: `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both the OT-based and Robust ECDSA schemes document that each `PresignOutput` must be consumed **exactly once**. However, the library enforces no such invariant at the type or API level. `PresignOutput` derives `Clone` and `Serialize/Deserialize`, and `rerandomize_presign` accepts it by shared reference (`&PresignOutput`), leaving the presignature fully intact after use. A malicious coordinator or a buggy caller can reuse the same presignature across two signing sessions with different messages, producing two ECDSA signatures that share a nonce. Standard nonce-reuse algebra then recovers the aggregate private key.

---

### Finding Description

Both `PresignOutput` types are plain, cloneable data structs with no "consumed" state:

**OT-based** (`src/ecdsa/ot_based_ecdsa/mod.rs`, lines 40–49):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,
    pub sigma: Scalar,
}
``` [1](#0-0) 

**Robust** (`src/ecdsa/robust_ecdsa/mod.rs`, lines 26–37):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}
``` [2](#0-1) 

`rerandomize_presign` in both schemes takes the presignature **by shared reference**, leaving the original untouched and reusable:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← shared reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { ... }
``` [3](#0-2) [4](#0-3) 

`RerandomizedPresignOutput` also derives `Clone`, so even the post-rerandomization value can be duplicated before being passed to `sign()` by value: [5](#0-4) [6](#0-5) 

Neither `sign()` entry point performs any check that the supplied presignature is fresh: [7](#0-6) [8](#0-7) 

The documentation acknowledges the invariant but relies entirely on the caller to honour it:

> "it's crucial that a presignature is never reused" [9](#0-8) 

> "Never reuse a presignature, even across failed, aborted, or partially completed signing sessions." [10](#0-9) 

> "Each output is consumed **exactly once** (one-time use)." [11](#0-10) 

The orchestration documentation further warns that without quorum-overlap guarantees, two independent groups can attempt to use the same output: [12](#0-11) 

---

### Impact Explanation

ECDSA security requires that the nonce `k` (encoded in `big_r = g^{1/k}`) is used for exactly one signature. If the same `PresignOutput` is used to produce two signatures `(R, s1)` and `(R, s2)` over messages `h1 ≠ h2`:

```
s1 = h1·k + Rx·σ  (mod q)
s2 = h2·k + Rx·σ  (mod q)
```

Subtracting: `k = (s1 − s2) / (h1 − h2)`, then `x = (s1 − h1·k) / (Rx·k)`.

The aggregate private key `x` is fully recovered. The Robust ECDSA security analysis explicitly confirms this attack vector:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks." [13](#0-12) 

**Impact class:** Critical — extraction of the aggregate private signing key.

---

### Likelihood Explanation

The attack is reachable by a **malicious coordinator** (an explicitly modelled adversary in this library). The coordinator orchestrates which presignature each participant uses and can instruct participants to call `rerandomize_presign` and `sign` twice with the same `PresignOutput` but different `(msg_hash, tweak)` arguments. Because `PresignOutput` is `Clone + Serialize`, it can be stored and replayed trivially. No cryptographic break or external compromise is required — only the ability to supply the same presignature struct to two signing invocations, which the API permits unconditionally.

---

### Recommendation

1. **Remove `Clone` from `PresignOutput` and `RerandomizedPresignOutput`** in both schemes. This makes accidental duplication a compile-time error.
2. **Change `rerandomize_presign` to consume `PresignOutput` by value** (`presignature: PresignOutput`), so the Rust ownership system enforces single-use at the call site.
3. **Optionally introduce a type-state wrapper** (e.g., `SingleUse<PresignOutput>`) that wraps the value in a `Option` and panics or errors on a second call to `take()`, providing a runtime safety net for cases where the value must cross serialization boundaries.

---

### Proof of Concept

```rust
// Both schemes: PresignOutput is Clone, rerandomize_presign takes &PresignOutput.
// A malicious coordinator can do:

let presign_output: PresignOutput = /* result of presigning phase */;

// First signing session: message h1, tweak ε1
let args1 = RerandomizationArguments { big_r: presign_output.big_r, tweak: tweak1, .. };
let rerandomized1 = RerandomizedPresignOutput::rerandomize_presign(&presign_output, &args1)?;
// ... run sign() → produces signature (R, s1) over h1

// Second signing session: SAME presign_output, different message h2
// presign_output is still valid because rerandomize_presign took &presign_output
let args2 = RerandomizationArguments { big_r: presign_output.big_r, tweak: tweak2, .. };
let rerandomized2 = RerandomizedPresignOutput::rerandomize_presign(&presign_output, &args2)?;
// ... run sign() → produces signature (R', s2) over h2
// Note: big_r is rerandomized by delta, but the underlying nonce k is the same.
// With two signatures sharing the same k, the private key x is recoverable.
```

The library provides no guard — `presign_output` remains fully usable after the first call to `rerandomize_presign` because the function signature is `fn rerandomize_presign(presignature: &PresignOutput, ...)`. [14](#0-13) [15](#0-14)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L40-49)
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
```

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L54-63)
```rust
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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L66-96)
```rust
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

        // delta . R
        let rerandomized_big_r = presignature.big_r * delta;

        //  (sigma + tweak * k) * delta^{-1}
        let rerandomized_sigma =
            (presignature.sigma + args.tweak.value() * presignature.k) * inv_delta;

        // k * delta^{-1}
        let rerandomized_k = presignature.k * inv_delta;

        Ok(Self {
            big_r: rerandomized_big_r.into(),
            k: rerandomized_k,
            sigma: rerandomized_sigma,
        })
    }
```

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

**File:** src/ecdsa/robust_ecdsa/mod.rs (L55-86)
```rust
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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L22-76)
```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let threshold = usize::from(threshold.into());
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

    // ensure number of participants during the signing phase is >= threshold
    if participants.len() < threshold {
        return Err(InitializationError::NotEnoughParticipantsForThreshold {
            threshold,
            participants: participants.len(),
        });
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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L18-19)
```rust
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L149-158)
```markdown
Before implementing or using the robust ECDSA scheme implemented here,
be aware that it is vulnerable to **split-view attacks** in the robust setting when the
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

**File:** src/ecdsa/ot_based_ecdsa/README.md (L12-12)
```markdown
Each output is consumed **exactly once** (one-time use).
```

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L64-79)
```markdown
## Discarding information

Each phase can be run many times in advance, recording the information
public information produced, as well as the list of parties which produced it.
Then, this output is consumed by having a set of parties use it
for a subsequent phase.
It's **critical** that the output is then destroyed, so that no other
group of parties attempts to re-use that output for another phase.
In particular, the parties need some way of agreeing on which
outputs have been created and used.
If the threshold $t_i$ is such that $N_{i} \leq 2t - 1$, then it's impossible
to have two non-overlapping quorums, so if each party locally registers the
fact that an output has been used, then agreement can be had not to
use a certain output.
Otherwise, you might have two independent groups of parties trying
to use the same output, which is bad.
```
