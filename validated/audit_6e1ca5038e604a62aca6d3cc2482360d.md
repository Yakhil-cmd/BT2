Looking at the external report's vulnerability class — **state/ownership mismatch where a resource can be "consumed" by one party while another party still believes it is valid** — I need to find an analog in the threshold-signatures codebase where a cryptographic resource (presignature, key share, etc.) can be used multiple times when it should be consumed exactly once.

Let me examine the presign/sign pipeline and the rerandomization API.

From the files I've read:

- `src/ecdsa/ot_based_ecdsa/mod.rs` lines 66–96: `RerandomizedPresignOutput::rerandomize_presign` takes `presignature: &PresignOutput` — a **shared reference**, not a consuming move.
- `src/ecdsa/ot_based_ecdsa/mod.rs` lines 40–49: `PresignOutput` derives `Clone`.
- `src/ecdsa/ot_based_ecdsa/sign.rs` lines 22–76: `sign()` takes `presignature: RerandomizedPresignOutput` **by value** (consumed once).
- `src/ecdsa/ot_based_ecdsa/presign.rs` lines 17–19: The comment explicitly states "it's crucial that a presignature is never reused."

The invariant is documented but not enforced at the type level: `rerandomize_presign` borrows `&PresignOutput` instead of consuming it, so the same `PresignOutput` can be rerandomized multiple times with different `RerandomizationArguments`, producing multiple `RerandomizedPresignOutput` values all sharing the same underlying nonce `k`.

---

### Title
`PresignOutput` Not Consumed After Rerandomization Enables Nonce Reuse and Private Key Extraction — (File: `src/ecdsa/ot_based_ecdsa/mod.rs`)

---

### Summary

`RerandomizedPresignOutput::rerandomize_presign` accepts `presignature: &PresignOutput` by shared reference rather than consuming it by value. Because the presignature is never invalidated after use, a malicious coordinator can rerandomize the same `PresignOutput` for two distinct signing sessions. The two resulting signatures share the same underlying nonce `k`, yielding a system of two linear equations in two unknowns (`k` and `sigma = k·x`) that directly reveals the aggregate private key `x`.

---

### Finding Description

In `src/ecdsa/ot_based_ecdsa/mod.rs`, the rerandomization entry point is:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // ← borrowed, NOT consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {
    if presignature.big_r != args.big_r {
        return Err(ProtocolError::IncompatibleRerandomizationInputs);
    }
    let delta = args.derive_randomness()?;
    ...
    let rerandomized_k     = presignature.k * inv_delta;
    let rerandomized_sigma = (presignature.sigma + args.tweak.value() * presignature.k) * inv_delta;
    ...
}
``` [1](#0-0) 

Because `presignature` is a shared reference, the same `PresignOutput` can be passed to `rerandomize_presign` an arbitrary number of times. `PresignOutput` also derives `Clone`, making it trivially copyable before passing to `sign`. [2](#0-1) 

By contrast, the downstream `sign()` function correctly consumes `RerandomizedPresignOutput` by value, so each rerandomized output can only be used once — but this protection is bypassed because the upstream `PresignOutput` is never invalidated. [3](#0-2) 

The library's own documentation acknowledges the invariant but does not enforce it: [4](#0-3) 

**Attack path (malicious coordinator):**

1. The coordinator orchestrates a presign session; all participants produce their `PresignOutput` shares (nonce shares `k_i`, `sigma_i`, public nonce `R`).
2. The coordinator constructs two distinct `RerandomizationArguments` — `args1` (tweak `t1`, message `m1`) and `args2` (tweak `t2`, message `m2`) — both referencing the same `big_r`.
3. The coordinator calls `rerandomize_presign(&presign_output, &args1)` and `rerandomize_presign(&presign_output, &args2)` on each participant's share (or instructs participants to do so), obtaining two `RerandomizedPresignOutput` values backed by the same `k`.
4. The coordinator runs two signing sessions, collecting signatures `(R1, s1)` and `(R2, s2)`.
5. Because the coordinator created both `args`, it knows `delta1` and `delta2`. It now solves the two-equation system below for the private key.

---

### Impact Explanation

Let `k` be the aggregate nonce and `sigma = k · x` (where `x` is the aggregate private key). After rerandomization with scalars `delta1`, `delta2` and tweaks `t1`, `t2`:

```
s1 · delta1 = (h1 + r1·t1) · k  +  r1 · sigma
s2 · delta2 = (h2 + r2·t2) · k  +  r2 · sigma
```

This is a 2×2 linear system over the scalar field with unknowns `k` and `sigma`. Since the coordinator chose `args1` and `args2`, it knows `delta1`, `delta2`, `t1`, `t2`, `r1`, `r2`, `h1`, `h2`. Solving gives `k` and `sigma`, and therefore `x = sigma · k⁻¹` — the full aggregate private signing key.

**Impact: Critical** — complete extraction of the aggregate private key, enabling unauthorized creation of valid threshold signatures for any message.

---

### Likelihood Explanation

The coordinator is a documented, first-class role in the library. A malicious coordinator needs only to:
- retain the `PresignOutput` (or clone it before passing to `sign`), and
- issue two signing requests referencing the same presignature.

No external assumptions, leaked keys, or cryptographic breaks are required. The API actively facilitates the attack by accepting `&PresignOutput` rather than `PresignOutput`.

---

### Recommendation

**Primary fix:** Change `rerandomize_presign` to consume the `PresignOutput` by value, making reuse a compile-time error:

```rust
pub fn rerandomize_presign(
    presignature: PresignOutput,          // ← consume by value
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> { ... }
```

**Secondary fix:** Remove the `Clone` derive from `PresignOutput` (and `PresignArguments`) to prevent callers from silently copying the nonce material before passing it:

```rust
// Before
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }

// After
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }
```

These two changes together enforce the "one-time use" invariant at the type level, mirroring the recommendation in the external report to "burn claimed ticket NFTs" — here, the presignature is cryptographically "burned" by being moved into the rerandomization call.

---

### Proof of Concept

```rust
// Coordinator holds presign_output after the offline phase
let presign_output: PresignOutput = run_presign_protocol(...);

// REUSE: rerandomize_presign takes &PresignOutput — presign_output is NOT consumed
let rerandomized1 = RerandomizedPresignOutput::rerandomize_presign(
    &presign_output,   // still valid after this call
    &args1,            // tweak t1, message m1
).unwrap();

let rerandomized2 = RerandomizedPresignOutput::rerandomize_presign(
    &presign_output,   // reused with the same underlying k!
    &args2,            // tweak t2, message m2
).unwrap();

// sign() consumes each RerandomizedPresignOutput once — but both share nonce k
let sig1 = run_sign_protocol(rerandomized1, msg1, ...); // (R1, s1)
let sig2 = run_sign_protocol(rerandomized2, msg2, ...); // (R2, s2)

// Coordinator knows delta1, delta2, t1, t2 — solve 2x2 system for x (private key)
// s1*delta1 = (h1 + r1*t1)*k + r1*sigma
// s2*delta2 = (h2 + r2*t2)*k + r2*sigma
// => x = sigma / k
```

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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L22-30)
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
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L17-19)
```rust
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```
