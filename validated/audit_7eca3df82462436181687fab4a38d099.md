### Title
`PresignOutput` Not Consumed After Rerandomization Enables Nonce-Reuse Secret Key Extraction — (`src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both `ot_based_ecdsa::RerandomizedPresignOutput::rerandomize_presign` and `robust_ecdsa::RerandomizedPresignOutput::rerandomize_presign` accept the `PresignOutput` as a shared reference (`&PresignOutput`) rather than consuming it by value. This means the Rust type system does not enforce the library's own documented invariant that each presignature must be used exactly once. A malicious coordinator can cause honest parties to rerandomize and sign with the same presignature under two different `(msg_hash, tweak)` pairs, producing signatures with multiplicatively related nonces from which the aggregate secret key can be recovered.

---

### Finding Description

The library's own documentation is unambiguous about the one-time-use requirement:

> "Each output is consumed **exactly once** (one-time use)."
> "It's **critical** that the output is then destroyed."
> "Never reuse a presignature, even across failed, aborted, or partially completed signing sessions."

Despite this, both `rerandomize_presign` implementations accept the presignature by shared reference:

**OT-based ECDSA** (`src/ecdsa/ot_based_ecdsa/mod.rs`, lines 66–96):
```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // shared reference — not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {
```

**Robust ECDSA** (`src/ecdsa/robust_ecdsa/mod.rs`, lines 55–86):
```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // shared reference — not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {
```

Because `PresignOutput` also derives `Clone`, any caller can trivially call `rerandomize_presign` on the same `PresignOutput` value multiple times with different `RerandomizationArguments`. There is no internal flag, consumed marker, or ownership transfer that would prevent this.

**Attack path (malicious coordinator):**

1. The coordinator orchestrates a presigning session; each honest party $P_i$ holds a `PresignOutput` containing their share of the nonce $(R, k_i, \sigma_i)$ (OT-based) or $(R, \alpha_i, \beta_i, c_i, e_i)$ (Robust).
2. The coordinator initiates **two concurrent signing sessions** referencing the same presignature, but with distinct `RerandomizationArguments`: session A uses $(h_A, \epsilon_A, \rho_A)$ and session B uses $(h_B, \epsilon_B, \rho_B)$.
3. Each honest party, having no mechanism to detect that their `PresignOutput` was already used, calls `rerandomize_presign` for both sessions — the API accepts both calls because the presignature is not consumed.
4. Each party sends their signature share $s_i^A$ and $s_i^B$ to the coordinator.
5. The coordinator obtains two valid signatures $(R_A, s_A)$ and $(R_B, s_B)$ where $R_A = \delta_A \cdot R$ and $R_B = \delta_B \cdot R$. The underlying nonce material is the same, scaled by known public deltas $\delta_A, \delta_B$. The security documentation explicitly confirms: *"the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks."*

This is the direct analog of the Vault.sol bug: just as `TCAPV2.burn()` was called without calling `modifyPosition()` to mark the debt as reduced (allowing repeated liquidation), here `rerandomize_presign` is called without consuming the `PresignOutput` (allowing repeated rerandomization of the same nonce material).

---

### Impact Explanation

**Critical.** Successful exploitation recovers the aggregate ECDSA secret key from two signatures produced under the same presignature nonce. This constitutes extraction of private signing shares / aggregate secret material. The recovered key allows the attacker to forge arbitrary signatures for any message under the threshold group's public key, permanently and completely compromising the key.

---

### Likelihood Explanation

**Medium.** The attacker must be the coordinator (a role that is reachable without privileged key material — any participant can be designated coordinator). The coordinator needs to initiate two signing sessions referencing the same presignature before honest parties detect the reuse. Because the library itself provides no reuse-detection mechanism and the API does not consume the presignature, honest parties have no in-library defense. The attack requires only standard protocol participation.

---

### Recommendation

Change both `rerandomize_presign` functions to consume the `PresignOutput` by value, so the Rust ownership system statically enforces one-time use:

```rust
// OT-based: src/ecdsa/ot_based_ecdsa/mod.rs
pub fn rerandomize_presign(
-   presignature: &PresignOutput,
+   presignature: PresignOutput,
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {

// Robust: src/ecdsa/robust_ecdsa/mod.rs
pub fn rerandomize_presign(
-   presignature: &PresignOutput,
+   presignature: PresignOutput,
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {
```

Additionally, remove the `Clone` derive from `PresignOutput` in both modules to prevent callers from cloning the value before passing it, which would circumvent the ownership enforcement.

---

### Proof of Concept

```rust
// Demonstrates that the same PresignOutput can be rerandomized twice
// with different arguments — no error, no consumption.
let presign_out: PresignOutput = /* result of presign protocol */;

let args_a = RerandomizationArguments::new(pk, tweak_a, msg_hash_a, presign_out.big_r, participants.clone(), entropy_a);
let args_b = RerandomizationArguments::new(pk, tweak_b, msg_hash_b, presign_out.big_r, participants.clone(), entropy_b);

// Both succeed — presign_out is not consumed
let rerand_a = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args_a).unwrap();
let rerand_b = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args_b).unwrap();

// A malicious coordinator now runs two signing sessions:
// session A with rerand_a and msg_hash_a
// session B with rerand_b and msg_hash_b
// The two resulting signatures (R_A, s_A) and (R_B, s_B) share
// multiplicatively related nonces (R_A = delta_A*R, R_B = delta_B*R),
// enabling standard nonce-reuse secret key recovery.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L65-70)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
```

**File:** src/ecdsa/robust_ecdsa/mod.rs (L39-52)
```rust
/// The output of the presigning protocol.
/// Contains the signature precomputed elements
/// independently of the message
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

**File:** src/ecdsa/robust_ecdsa/mod.rs (L54-60)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
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
