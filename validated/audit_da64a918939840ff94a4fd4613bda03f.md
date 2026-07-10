### Title
No-Enforcement Presignature Invalidation Allows Nonce-Reuse Private Key Extraction - (File: `src/ecdsa/robust_ecdsa/mod.rs`, `src/ecdsa/ot_based_ecdsa/mod.rs`)

---

### Summary

Both the Robust ECDSA and OT-based ECDSA schemes expose `RerandomizedPresignOutput::rerandomize_presign()` as a function that accepts `presignature: &PresignOutput` by shared reference. This means the same `PresignOutput` can be rerandomized an unlimited number of times, producing multiple distinct `RerandomizedPresignOutput` values from the same underlying nonce material. The library provides no mechanism — neither type-system enforcement nor runtime state — to prevent a presignature from being consumed more than once. The documentation explicitly identifies presignature reuse as a Critical security requirement, and the codebase's own security notes confirm that reuse leads to private key extraction via nonce-reuse attacks.

---

### Finding Description

**Root cause — `rerandomize_presign` accepts presignature by shared reference:**

In `src/ecdsa/robust_ecdsa/mod.rs`:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // shared reference — can be called N times
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {
``` [1](#0-0) 

And identically in `src/ecdsa/ot_based_ecdsa/mod.rs`: [2](#0-1) 

Because the function takes `&PresignOutput` (not `PresignOutput`), the caller retains ownership and can invoke `rerandomize_presign` repeatedly with different `(h, ε, ρ)` arguments, producing multiple `RerandomizedPresignOutput` values that all share the same underlying nonce `k` (and `sigma`/`alpha`/`beta`). No "used" flag, no move-consumption, and no runtime check prevents this.

**`PresignOutput` also derives `Clone`, compounding the issue:** [3](#0-2) [4](#0-3) 

Even if `rerandomize_presign` were changed to consume by value, the `Clone` derive allows callers to trivially duplicate the presignature before passing it.

**The `sign()` functions do not check for prior use:**

`src/ecdsa/robust_ecdsa/sign.rs` enforces `N = 2t+1` and `msg_hash ≠ 0` to block split-view attacks within a single session, but performs no check that the presignature has not already been used in a prior session. [5](#0-4) 

**Concrete attack path (malicious coordinator):**

1. Coordinator participates in presigning; all honest parties produce their `PresignOutput` shares.
2. Coordinator calls `rerandomize_presign(&presig, args1)` → `RerandomizedPresignOutput1` for message `h1`.
3. Coordinator calls `rerandomize_presign(&presig, args2)` → `RerandomizedPresignOutput2` for message `h2` (same `presig`).
4. Coordinator runs signing session 1 with `RerandomizedPresignOutput1`; honest parties contribute `s_i` shares.
5. Coordinator runs signing session 2 with `RerandomizedPresignOutput2`; honest parties contribute `s_i` shares again.
6. Coordinator now holds two valid ECDSA signatures `(R1, s1)` and `(R2, s2)` whose nonces are multiplicatively related (both derived from the same base `R`).
7. Standard ECDSA nonce-reuse algebra recovers the aggregate private key `x`.

---

### Impact Explanation

The library's own security documentation confirms the impact:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks." [6](#0-5) 

This maps directly to the Critical allowed impact: **extraction/reconstruction of the aggregate private signing key**. The attack requires no cryptographic break — only the ability to invoke `rerandomize_presign` twice on the same `PresignOutput`, which the API permits unconditionally.

The OT-based ECDSA orchestration documentation also explicitly marks presignature outputs as one-time-use and warns that reuse is "bad": [7](#0-6) 

---

### Likelihood Explanation

**Likelihood: Moderate.**

- A malicious coordinator is an explicitly in-scope threat actor per `RESEARCHER.md`.
- The coordinator controls which `(h, ε, ρ)` arguments are passed to `rerandomize_presign` and can run two signing sessions against the same presignature without any honest participant being able to detect or prevent it.
- A careless but honest library caller can also trigger this accidentally after a failed or aborted signing session, since the library provides no signal that the presignature has been consumed.
- The `rerandomize_presign` API requires no special privilege — it is a public function callable by any library user.

---

### Recommendation

1. **Change `rerandomize_presign` to consume `PresignOutput` by value** (`presignature: PresignOutput`), so Rust's ownership system prevents a second call on the same value.
2. **Remove `Clone` from `PresignOutput` and `RerandomizedPresignOutput`** (or gate it behind a `#[cfg(test)]` or explicit `unsafe`-equivalent marker) so callers cannot trivially duplicate presignature material.
3. If serialization/storage requires `Clone`, introduce a wrapper type (e.g., `StoredPresignOutput`) that is explicitly marked as requiring single-use discipline, separate from the type passed to `sign()`.

---

### Proof of Concept

```rust
// Attacker (malicious coordinator) holds presig: PresignOutput
// from a completed presigning round.

// Rerandomize TWICE with different (h, ε) — no error, no invalidation
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presig, &args1).unwrap();
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presig, &args2).unwrap();

// Run two signing sessions — honest participants cannot detect reuse
let sig1 = run_sign_session(rerand1, h1, participants);  // (R1, s1)
let sig2 = run_sign_session(rerand2, h2, participants);  // (R2, s2)

// R1 = R^delta1, R2 = R^delta2 — multiplicatively related nonces
// Standard ECDSA nonce-reuse recovery extracts private key x
```

The `rerandomize_presign` call on line 55–86 of `src/ecdsa/robust_ecdsa/mod.rs` accepts `&PresignOutput` and returns a fresh `RerandomizedPresignOutput` each time with no side-effect on the source, making the above sequence valid Rust with no unsafe code. [8](#0-7) [9](#0-8)

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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L65-96)
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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L84-95)
```rust
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
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L150-158)
```markdown
be aware that it is vulnerable to **split-view attacks** in the robust setting when the
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.

Moreover, due to protocol modifications relative to [[DJNPO20](https://eprint.iacr.org/2020/501)] (notably signature-share
linearization), **a novel split-view attack exists that can extract the secret key using as
few as $2t + 2$ presigning participants**, with as few as two signing sessions.
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
