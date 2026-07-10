### Title
Missing Presignature Consumption in `rerandomize_presign` Allows Nonce Reuse and Private Key Extraction — (`src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both ECDSA schemes expose `rerandomize_presign` as a function that takes `presignature: &PresignOutput` by shared reference, and `PresignOutput` derives `Clone` + `Serialize/Deserialize`. There is no "used" state flag anywhere in the library. A malicious coordinator can instruct participants to rerandomize and sign with the same `PresignOutput` twice under different `(msg_hash, tweak, participants)` contexts, producing two ECDSA signatures that share a multiplicatively related nonce. Standard ECDSA nonce-reuse algebra then recovers the private key.

This is the direct analog to the `InflationaryVest.vy` bug: in that contract `self.claimed` existed but was never updated, allowing infinite re-claims of the same allocation. Here, `PresignOutput` is the one-time-use resource, but no consumed/used state is ever set, allowing the same presignature to be rerandomized and signed an unlimited number of times.

---

### Finding Description

**Root cause — OT-based ECDSA:**

`PresignOutput` is declared `Clone + Serialize + Deserialize`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,
    pub sigma: Scalar,
}
```

`rerandomize_presign` takes it by shared reference, never consuming or invalidating it:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // <-- reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {
```

**Root cause — Robust ECDSA:**

Identical pattern in `src/ecdsa/robust_ecdsa/mod.rs`:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // <-- reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {
```

The library's own documentation acknowledges the invariant but does not enforce it in code:

> "It's **critical** that the output is then destroyed, so that no other group of parties attempts to re-use that output for another phase."
> "Never reuse a presignature, even across failed, aborted, or partially completed signing sessions."

The `sign()` functions for both schemes take `presignature: RerandomizedPresignOutput` by value, which would consume the rerandomized output — but `RerandomizedPresignOutput` also derives `Clone`, and more critically, the underlying `PresignOutput` is never consumed by `rerandomize_presign`, so it can be rerandomized again with different arguments at any time.

---

### Impact Explanation

**Critical — Extraction of private signing shares.**

Two ECDSA signatures produced from the same presignature nonce `k` but different messages `h1`, `h2` satisfy:

```
s1 = h1·k_inv + Rx·sigma_inv   (after rerandomization with delta1)
s2 = h2·k_inv + Rx·sigma_inv   (after rerandomization with delta2)
```

Because `delta` is deterministic (HKDF of public inputs), an attacker who controls the signing contexts can compute both `delta1` and `delta2`, relate the two signatures algebraically, and solve for the secret key share. The security documentation in `docs/ecdsa/robust_ecdsa/signing.md` lines 150–158 explicitly confirms this leads to full private key recovery.

---

### Likelihood Explanation

A **malicious coordinator** is an explicitly in-scope attacker role. The coordinator:

1. Orchestrates presigning to obtain a `PresignOutput` per participant.
2. Instructs participants to call `rerandomize_presign(presig, args1)` and then `sign()` for message `h1`.
3. Instructs the same participants to call `rerandomize_presign(presig, args2)` and then `sign()` for message `h2` using the **same** `PresignOutput`.
4. Collects both signatures and recovers the private key.

Participants have no library-enforced mechanism to detect or refuse step 3. The `PresignOutput` carries no consumed/used marker; the API accepts it unconditionally on every call.

For the robust ECDSA scheme, the `N1 = N2 = 2t+1` enforcement in `sign()` prevents split-view attacks across *different* subsets, but does **not** prevent the *same* subset signing twice with the same presignature — the documented attack still applies.

---

### Recommendation

`rerandomize_presign` should consume the `PresignOutput` by value rather than by reference, so that Rust's ownership system enforces single-use at compile time:

```rust
// Before (both schemes):
pub fn rerandomize_presign(
    presignature: &PresignOutput,
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>

// After:
pub fn rerandomize_presign(
    presignature: PresignOutput,   // consumed by value
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

Additionally, `PresignOutput` should not derive `Clone` (or the `Clone` impl should be gated behind a `#[cfg(test)]` attribute), so that callers cannot trivially duplicate the one-time-use material before passing it.

---

### Proof of Concept

```
1. Run presigning for participants [P1, P2, P3] with max_malicious=1 (N=3=2t+1).
   Each Pi holds PresignOutput { big_r: R, k: k_i, sigma: sigma_i }.

2. Coordinator constructs args1 = RerandomizationArguments { msg_hash: h1, tweak: ε1, ... }
   Each Pi calls: rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presig_i, &args1)
   Each Pi calls: sign(..., rerand1, h1_scalar) → signature (R1, s1) produced.

3. Coordinator constructs args2 = RerandomizationArguments { msg_hash: h2, tweak: ε2, ... }
   Each Pi calls: rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presig_i, &args2)
   // presig_i is still valid — it was never consumed or marked used
   Each Pi calls: sign(..., rerand2, h2_scalar) → signature (R2, s2) produced.

4. Coordinator holds (R1, s1) and (R2, s2) with related nonces.
   Using known delta1, delta2, h1, h2, Rx: solve for x (private key).
```

The library provides no mechanism to prevent step 3 from succeeding. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L65-72)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
        }
```

**File:** src/ecdsa/robust_ecdsa/mod.rs (L54-62)
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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-177)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.
```
