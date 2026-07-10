### Title
`rerandomize_presign()` Does Not Consume `PresignOutput`, Enabling Nonce Reuse and Secret Key Extraction - (`src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both `RerandomizedPresignOutput::rerandomize_presign()` implementations accept `presignature: &PresignOutput` (a shared reference) rather than consuming the `PresignOutput` by value. This is the direct analog of the Bribe bug: just as `tokenRewardsPerEpoch[token][epochStart]` was read but never zeroed, the presignature nonce material is read but never invalidated. A caller can invoke `rerandomize_presign()` multiple times on the same `PresignOutput` with different `RerandomizationArguments`, producing multiple `RerandomizedPresignOutput` values that all derive from the same underlying nonce `k`. Using these in separate signing sessions with different messages yields multiplicatively related nonces, enabling full secret key recovery via standard ECDSA nonce-reuse techniques.

---

### Finding Description

In `src/ecdsa/ot_based_ecdsa/mod.rs`, `RerandomizedPresignOutput::rerandomize_presign` is declared as:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,       // shared reference — NOT consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
``` [1](#0-0) 

The same pattern appears in `src/ecdsa/robust_ecdsa/mod.rs`:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,       // shared reference — NOT consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
``` [2](#0-1) 

Because the function borrows `presignature` rather than taking ownership, the caller retains the `PresignOutput` after the call and can invoke `rerandomize_presign` again with a different `args` (different tweak `ε` or different `big_r`-derived randomness). Each invocation produces a fresh `RerandomizedPresignOutput` whose nonce is a scalar multiple of the original nonce `k`:

- Call 1: `big_r₁ = δ₁·R`, `k₁ = k·δ₁⁻¹`
- Call 2: `big_r₂ = δ₂·R`, `k₂ = k·δ₂⁻¹`

The ratio `k₁/k₂ = δ₂/δ₁` is fully known to the attacker (both `δ` values are derived from attacker-controlled `args`). This is precisely the "multiplicatively related nonces" scenario documented as catastrophic in the security notes. [3](#0-2) 

The `PresignOutput` type is also `Clone`, meaning even a by-value API could be trivially circumvented by cloning before passing. However, the by-reference API makes the reuse path the default, zero-friction path. [4](#0-3) 

The OT-based README and orchestration documentation explicitly state that each presignature output is "one-time use" and "it's **critical** that the output is then destroyed," but the API provides no enforcement of this invariant. [5](#0-4) 

The robust ECDSA security notes confirm the exact attack:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks." [6](#0-5) 

---

### Impact Explanation

Two signatures produced from the same `PresignOutput` with different messages `h₁ ≠ h₂` satisfy:

```
s₁ = h₁·k₁ + Rx·σ₁
s₂ = h₂·k₂ + Rx·σ₂
```

where `k₁ = k·δ₁⁻¹`, `k₂ = k·δ₂⁻¹`, and `σ` terms are similarly related. Because `δ₁` and `δ₂` are known (derived from the attacker-supplied `RerandomizationArguments`), the system of equations is solvable for the secret key share. This constitutes **Critical: Extraction, reconstruction, or disclosure of private signing shares / nonce material**.

---

### Likelihood Explanation

Any participant who holds a `PresignOutput` — which is the normal output of a completed presigning round — can trigger this unilaterally. No coordination with other participants is required to perform the double-rerandomization. The `PresignOutput` struct is `pub`, `Clone`, and `Serialize`/`Deserialize`, so it can be stored and reused across sessions. A malicious participant or a compromised application layer that stores presignatures (e.g., in a database for later use) will naturally encounter this path.

---

### Recommendation

Change both `rerandomize_presign` signatures to consume the `PresignOutput` by value, enforcing single-use at the type level:

```rust
// Before (ot_based_ecdsa/mod.rs and robust_ecdsa/mod.rs)
pub fn rerandomize_presign(
    presignature: &PresignOutput,
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>

// After
pub fn rerandomize_presign(
    presignature: PresignOutput,   // consumed — cannot be reused
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

Additionally, remove the `Clone` derive from `PresignOutput` in both modules to prevent callers from cloning before passing, making single-use a compile-time guarantee rather than a documentation note. [7](#0-6) 

---

### Proof of Concept

1. Run the presigning protocol to obtain `presign_out: PresignOutput` (OT-based or robust).
2. Construct two distinct `RerandomizationArguments` with different tweaks: `args1` (tweak `ε₁`) and `args2` (tweak `ε₂`).
3. Call `RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args1)` → `rp1`.
4. Call `RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args2)` → `rp2`. *(The original `presign_out` is still valid — it was never consumed.)*
5. Use `rp1` to sign message `h₁` and `rp2` to sign message `h₂ ≠ h₁`.
6. Both signatures share nonce material derived from the same `k`. Since `δ₁` and `δ₂` are known, the relationship `k₁ = k·δ₁⁻¹` and `k₂ = k·δ₂⁻¹` allows solving for the secret key share from the two signature equations.

The `rerandomize_presign` function in both modules accepts `&PresignOutput` and returns without modifying or invalidating the input, making step 4 compile and execute without error. [8](#0-7) [9](#0-8)

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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L147-158)
```markdown
# Security considerations

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
