### Title
Presignature Not Consumed on Use Enables Nonce-Reuse Secret Key Extraction — (`src/ecdsa/robust_ecdsa/mod.rs`, `src/ecdsa/ot_based_ecdsa/mod.rs`)

---

### Summary

Both the robust ECDSA and OT-based ECDSA schemes claim each `PresignOutput` is "one-time use," but neither the library nor the `rerandomize_presign` API enforces this. `rerandomize_presign` accepts `&PresignOutput` (a shared reference), leaving the original presignature live and re-rerandomizable. A malicious coordinator can drive honest participants through two signing sessions that both consume shares derived from the same underlying nonce `R`, producing two signatures with multiplicatively related nonces. Standard ECDSA nonce-reuse algebra then recovers the aggregate secret key.

---

### Finding Description

`RerandomizedPresignOutput::rerandomize_presign` is defined as:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // shared reference — NOT consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {
``` [1](#0-0) 

Because the function borrows rather than moves `PresignOutput`, the caller retains the value and can call `rerandomize_presign` again with different `RerandomizationArguments` (different `msg_hash`, `tweak`, or `entropy`). The library provides no consumed-flag, no nonce-tracking map, and no ownership-transfer mechanism to prevent this.

Both `PresignOutput` types derive `Clone`, making accidental or deliberate duplication trivial: [2](#0-1) [3](#0-2) 

The robust ECDSA `sign` function accepts a `RerandomizedPresignOutput` by value (consuming the rerandomized copy), but this does not prevent the underlying `PresignOutput` from being rerandomized a second time: [4](#0-3) 

The security documentation explicitly acknowledges the attack class but relies entirely on the caller to prevent it:

> "Never reuse a presignature, even across failed, aborted, or partially completed signing sessions." [5](#0-4) 

The library also documents the novel split-view variant enabled by signature-share linearization:

> "a novel split-view attack exists that can extract the secret key using as few as 2t+2 presigning participants, with as few as two signing sessions." [6](#0-5) 

The `N1 = N2 = 2t+1` enforcement in `sign` prevents *different subsets* from signing with the same presignature, but it does **not** prevent the *same* `2t+1` participants from being driven through two sequential signing sessions using the same `PresignOutput`: [7](#0-6) 

---

### Impact Explanation

Two signatures produced from the same underlying nonce `R` satisfy:

```
s1 = δ1⁻¹ · (α·h1 + β·Rx1 + e)   (nonce = R^δ1)
s2 = δ2⁻¹ · (α·h2 + β·Rx2 + e)   (nonce = R^δ2)
```

Because `δ1` and `δ2` are both derived from the same `R` via HKDF, the nonces are multiplicatively related. Standard ECDSA nonce-reuse linear algebra over the two equations recovers the aggregate secret scalar `x`, constituting **full extraction of the aggregate private key** — a Critical impact matching "Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material." [8](#0-7) 

---

### Likelihood Explanation

The coordinator role is reachable by any participant in the protocol without privileged assumptions. A malicious coordinator:

1. Completes presigning with honest participants, each holding `PresignOutput { big_r: R, … }`.
2. Constructs `RerandomizationArguments` with `(h1, ε1, ρ1)` and drives signing session 1 — honest participants rerandomize their `PresignOutput` and submit shares.
3. Immediately constructs `RerandomizationArguments` with `(h2, ε2, ρ2)` and drives signing session 2 — honest participants rerandomize the **same** `PresignOutput` again (they have no mechanism to detect reuse) and submit shares.
4. The coordinator holds two signatures with related nonces and recovers the secret key.

Honest participants cannot detect the reuse: after rerandomization, `big_r` is `R^δ`, which differs between sessions, and the library exposes no API to register or check a presignature as consumed. [9](#0-8) 

---

### Recommendation

Change `rerandomize_presign` to consume the `PresignOutput` by value, making reuse a compile-time error:

```rust
pub fn rerandomize_presign(
    presignature: PresignOutput,   // moved, not borrowed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { … }
```

Remove the `Clone` derive from both `PresignOutput` types so that callers cannot duplicate the value before passing it. Apply the same ownership-transfer pattern to the OT-based `PresignOutput`. This mirrors the documented invariant ("consumed exactly once") at the type-system level and eliminates the replay surface without requiring any runtime state tracking. [10](#0-9) [11](#0-10) 

---

### Proof of Concept

```
// Attacker is the coordinator.
// Presigning has completed; each honest participant holds presign_output: PresignOutput.

// Session 1 — honest participants rerandomize and sign
let args1 = RerandomizationArguments::new(pk, tweak1, h1, presign_output.big_r, participants, rho1);
let rerandomized1 = RerandomizedPresignOutput::rerandomize_presign(&presign_output, &args1)?;
// ... drive signing protocol, collect (R^δ1, s1)

// Session 2 — same presign_output is still live; honest participants rerandomize again
let args2 = RerandomizationArguments::new(pk, tweak2, h2, presign_output.big_r, participants, rho2);
let rerandomized2 = RerandomizedPresignOutput::rerandomize_presign(&presign_output, &args2)?;
// ... drive signing protocol, collect (R^δ2, s2)

// Attacker now holds two signatures with multiplicatively related nonces.
// Standard ECDSA nonce-reuse recovery extracts the aggregate secret key x.
```

The `&presign_output` borrow on both calls compiles without error because `PresignOutput` is never consumed. No runtime check in `rerandomize_presign` or `sign` detects or prevents the second use. [1](#0-0) [12](#0-11)

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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L29-32)
```rust
/// To reduce risk in this implementation, require `N1 = N2 = 2 * max_malicious + 1`,
/// ensure all participants agree on `(msg_hash, tweak, participants)` when creating
/// `RerandomizedPresignOutput`, never reuse a presignature, and do not sign with
/// `msg_hash == 0`.
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L33-41)
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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L150-154)
```markdown
be aware that it is vulnerable to **split-view attacks** in the robust setting when the
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L156-158)
```markdown
Moreover, due to protocol modifications relative to [[DJNPO20](https://eprint.iacr.org/2020/501)] (notably signature-share
linearization), **a novel split-view attack exists that can extract the secret key using as
few as $2t + 2$ presigning participants**, with as few as two signing sessions.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-177)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.
```

**File:** src/ecdsa/robust_ecdsa/README.md (L12-12)
```markdown
Each presignature is consumed **exactly once** (one-time use).
```

**File:** src/ecdsa/ot_based_ecdsa/README.md (L12-12)
```markdown
Each output is consumed **exactly once** (one-time use).
```
