### Title
Missing Single-Use Enforcement on `PresignOutput` Enables Presignature Reuse and Secret Key Extraction — (`src/ecdsa/robust_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/sign.rs`)

---

### Summary

The `PresignOutput` type in the Robust ECDSA scheme derives `Clone`, `Serialize`, and `Deserialize` with no single-use enforcement. The security documentation explicitly requires "Never reuse a presignature, even across failed, aborted, or partially completed signing sessions," but the library provides no mechanism to enforce this. A malicious coordinator can rerandomize the same `PresignOutput` for two different messages and run two signing sessions against the same honest participant set, obtaining two signatures with multiplicatively related nonces. This enables full secret key extraction via standard ECDSA nonce-reuse attacks.

---

### Finding Description

The Robust ECDSA presigning protocol produces a `PresignOutput` containing the shared nonce material `(big_r, c, e, alpha, beta)`. This struct is declared with `#[derive(Clone, Serialize, Deserialize)]`:

```rust
// src/ecdsa/robust_ecdsa/mod.rs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}
```

The `sign` function accepts a `RerandomizedPresignOutput` (produced by calling `rerandomize_presign` on a `PresignOutput`) and a `msg_hash`, but performs no check that the underlying presignature has not been previously used:

```rust
// src/ecdsa/robust_ecdsa/sign.rs
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: impl Into<MaxMalicious>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError>
```

The `sign` function enforces `participants.len() == 2*max_malicious+1` and `msg_hash != 0`, but there is no check that the `big_r` embedded in `presignature` has not appeared in a prior signing session. Because `PresignOutput` is `Clone` and serializable, a coordinator can:

1. Participate in presigning to obtain a `PresignOutput` containing nonce `R = g^{1/k}`.
2. Call `rerandomize_presign(presignature, args_1)` with `(msg_hash=h1, tweak=ε1)` → `RerandomizedPresignOutput1` (nonce `R'_1 = δ_1 · R`).
3. Call `rerandomize_presign(presignature, args_2)` with `(msg_hash=h2, tweak=ε2)` → `RerandomizedPresignOutput2` (nonce `R'_2 = δ_2 · R`).
4. Run signing session 1 with the full `N = 2t+1` participant set, collecting all `s_i` shares for `h1`.
5. Run signing session 2 with the same `N = 2t+1` participant set, collecting all `s_i` shares for `h2`.
6. Recover the secret key from the two resulting signatures, whose nonces satisfy `R'_2 = (δ_2/δ_1) · R'_1` — a multiplicative nonce relationship sufficient for standard ECDSA key recovery.

The security documentation explicitly acknowledges this attack class:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks."
> "a novel split-view attack exists that can extract the secret key using as few as 2t+2 presigning participants, with as few as two signing sessions."

The existing code mitigations (`participants.len() == 2t+1`, `msg_hash != 0`) address split-view attacks involving *different* participant subsets, but do not prevent a coordinator from reusing the same presignature across two sessions with the *same* participant set.

The same structural issue exists in the OT-based ECDSA scheme, where `PresignOutput` and `RerandomizedPresignOutput` are also `Clone`:

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput { ... }
```

---

### Impact Explanation

A malicious coordinator who participates in a single presigning session can reuse the resulting `PresignOutput` across two signing sessions for different messages. The two resulting ECDSA signatures have multiplicatively related nonces (`R'_2 = (δ_2/δ_1) · R'_1`), which is sufficient to recover the full aggregate secret key via standard ECDSA nonce-reuse algebra. This constitutes **Critical: Extraction, reconstruction, or disclosure of private signing shares / aggregate secret material**.

---

### Likelihood Explanation

The coordinator role is a designated participant in every signing session — not a privileged external actor. Any one of the `2t+1` signing participants can act as coordinator. A single malicious participant among the signers is sufficient to trigger this attack. The attack requires only two sequential signing sessions (which is normal operational behavior) and no out-of-band capabilities. The `PresignOutput` type's `Clone` + `Serialize/Deserialize` derivation makes the reuse trivially achievable in any orchestration layer built on top of this library.

---

### Recommendation

1. **Consume `PresignOutput` on use**: Replace `Clone` with a move-only type, or wrap it in a newtype that implements `Drop` to zeroize and cannot be cloned. This mirrors the "one-time use" guarantee stated in the documentation.
2. **Bind presignature to signing session at creation**: Embed a unique session identifier (e.g., a random nonce generated during presigning) into `PresignOutput`. Require `sign` to verify that the session ID in the presignature matches the current session, preventing silent reuse.
3. **Audit `RerandomizedPresignOutput`**: Apply the same move-only or session-binding treatment to `RerandomizedPresignOutput` to prevent a coordinator from distributing the same rerandomized presignature to multiple signing sessions.

---

### Proof of Concept

```
// Attacker is the coordinator in a 2t+1 = 3-party Robust ECDSA setup.

// Step 1: Run presigning normally.
let presign_output: PresignOutput = run_presigning(participants, me, args);

// Step 2: Rerandomize for message h1.
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(
    &presign_output,  // <-- original presignature
    &RerandomizationArguments { msg_hash: h1, tweak: eps1, ... }
)?;

// Step 3: Rerandomize the SAME presign_output for message h2.
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(
    &presign_output,  // <-- same presignature, no error
    &RerandomizationArguments { msg_hash: h2, tweak: eps2, ... }
)?;

// Step 4: Run two signing sessions. Both pass all validation checks
// (N == 2t+1, msg_hash != 0). Honest participants sign both sessions.
let sig1 = run_sign(participants, coordinator, rerand1, h1);
let sig2 = run_sign(participants, coordinator, rerand2, h2);

// Step 5: Recover secret key from (sig1, sig2) using nonce-reuse algebra.
// R'_2 = (delta_2 / delta_1) * R'_1 => multiplicatively related nonces.
let secret_key = recover_key_from_related_nonces(sig1, sig2, h1, h2, delta1, delta2);
```

The `PresignOutput` struct's `Clone` derivation means step 3 compiles and executes without any error or warning. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L23-41)
```rust
///
/// WARNING:
/// This robust ECDSA scheme is vulnerable to split-view attacks in the robust
/// setting if different subsets of participants sign different `(msg_hash, tweak)`
/// values using shares derived from the same presignature (i.e., different
/// rerandomization inputs for the same presignature).
/// To reduce risk in this implementation, require `N1 = N2 = 2 * max_malicious + 1`,
/// ensure all participants agree on `(msg_hash, tweak, participants)` when creating
/// `RerandomizedPresignOutput`, never reuse a presignature, and do not sign with
/// `msg_hash == 0`.
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: impl Into<MaxMalicious>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L147-178)
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

To reduce the risk of accidental misuse, enforce the following constraints:

1. **Use exactly $N_1 = N_2 = 2t + 1$ participants for both presigning and signing.**
   Do **not** allow any deviation from this value. In particular:

   * Do **not** allow $N_1 > 2t + 1$, and
   * Do **not** allow $N_2 < N_1$.

   Allowing larger presigning sets or smaller signing sets enables split-view and
   presignature-reuse attacks when a coordinator can run parallel or partially overlapping
   signing sessions.

2. **Ensure all participants agree on $(h, \epsilon)$ and the signing set.**
   The coordinator must not be able to present different message hashes, tweaks, or
   participant lists to different signers.

3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.

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

**File:** src/ecdsa/ot_based_ecdsa/README.md (L11-12)
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
