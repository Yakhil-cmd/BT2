### Title
Presignature Reuse Enables Secret Key Extraction via Split-View Attack — (`src/ecdsa/ot_based_ecdsa/mod.rs`)

---

### Summary

The `PresignOutput` type in the OT-based ECDSA module derives `Clone` and `rerandomize_presign` accepts a shared reference `&PresignOutput` rather than consuming it. This means the library's own API does not enforce the single-use invariant that its security documentation explicitly requires. A malicious coordinator — or a buggy orchestration layer — can rerandomize the same presignature with two different `(h, ε)` pairs, run two signing sessions, and recover the aggregate secret key via standard ECDSA nonce-reuse arithmetic. The library's own security documentation acknowledges this attack class but provides no code-level enforcement.

---

### Finding Description

**Root cause — `PresignOutput` is `Clone` and `rerandomize_presign` does not consume it:**

`PresignOutput` in `src/ecdsa/ot_based_ecdsa/mod.rs` derives `Clone`: [1](#0-0) 

`RerandomizedPresignOutput` also derives `Clone`: [2](#0-1) 

`rerandomize_presign` takes a shared reference `&PresignOutput`, not ownership: [3](#0-2) 

Because the function borrows rather than moves the presignature, the caller retains the original `PresignOutput` after the call and can invoke `rerandomize_presign` again with a different `RerandomizationArguments` (i.e., a different message hash `h` or tweak `ε`). The `Clone` derive makes this even more explicit: any caller can `.clone()` a `PresignOutput` before passing it anywhere, trivially enabling reuse.

**Exploit path:**

1. A malicious coordinator (or a buggy orchestration layer) holds a `PresignOutput` `P` produced by the presigning protocol.
2. It calls `RerandomizedPresignOutput::rerandomize_presign(&P, args1)` with `(h₁, ε₁)` → `R₁`.
3. It calls `RerandomizedPresignOutput::rerandomize_presign(&P, args2)` with `(h₂, ε₂)` → `R₂`.
4. It runs two signing sessions: one with `R₁` producing signature `(r, s₁)`, one with `R₂` producing `(r, s₂)`.
5. Because both sessions share the same underlying nonce commitment `big_r` (only linearly scaled by `δ₁` and `δ₂` respectively), the two signatures have multiplicatively related nonces. Standard ECDSA nonce-reuse algebra then recovers the aggregate secret key `x`.

The library's own security documentation explicitly describes this attack class and states the requirement: [4](#0-3) 

The mitigation documented there — enforcing `N₁ = N₂ = 2t+1` and rejecting `h = 0` — is implemented in `robust_ecdsa/sign.rs`: [5](#0-4) 

However, these checks address only the *split-view participant-set* variant of the attack. They do **not** prevent a coordinator from calling `rerandomize_presign` twice on the same `PresignOutput` with different `(h, ε)` values, which is the direct analog of the H-04 "reuse the same signatures to call `setComplete()` multiple times" pattern.

---

### Impact Explanation

**Severity: Critical.**

Reusing a presignature with two different `(h, ε)` pairs produces two ECDSA signatures whose nonces are related by a known scalar. This is sufficient to reconstruct the aggregate secret key `x` using standard nonce-reuse arithmetic (`x = (s₁·k₁ - s₂·k₂) / (r·(λ₁ - λ₂))` after accounting for rerandomization scalars). The extracted key is the full threshold secret, not just one party's share. This falls squarely within the allowed critical impact: *"Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets."*

---

### Likelihood Explanation

**Likelihood: High** for a malicious coordinator; **Medium** for an honest but buggy orchestration layer.

The coordinator role is explicitly part of the protocol model (it aggregates partial signatures in both OT-based and robust ECDSA). A malicious coordinator needs only to call `rerandomize_presign` twice — a single-line Rust call — before dispatching signing sessions. No privileged key material is required beyond what the coordinator legitimately holds. The `Clone` derive on `PresignOutput` means even an honest orchestration layer can accidentally reuse a presignature by cloning it for retry logic, error recovery, or parallel session management.

---

### Recommendation

1. **Remove `Clone` from `PresignOutput` and `RerandomizedPresignOutput`.** This is the strongest enforcement: it makes reuse a compile-time error.

2. **Change `rerandomize_presign` to consume `PresignOutput` by value** (take `presignature: PresignOutput` instead of `presignature: &PresignOutput`). This enforces the single-use invariant at the type level — once rerandomized, the presignature is moved and cannot be used again.

3. **If `Clone` must be retained for serialization/testing purposes**, gate it behind a `#[cfg(test)]` attribute so it is unavailable in production builds.

---

### Proof of Concept

```rust
// Attacker is the coordinator. Holds a legitimately produced PresignOutput P.
let p: PresignOutput = /* produced by presigning protocol */;

// Step 1: rerandomize with message h1
let r1 = RerandomizedPresignOutput::rerandomize_presign(&p, &args_h1).unwrap();

// Step 2: rerandomize SAME presignature with message h2 — no error, no check
let r2 = RerandomizedPresignOutput::rerandomize_presign(&p, &args_h2).unwrap();

// Step 3: run two signing sessions → two signatures with related nonces
// Step 4: apply standard ECDSA nonce-reuse formula → recover secret key x
```

The call at step 2 succeeds because `rerandomize_presign` takes `&PresignOutput` and the library has no mechanism to detect or prevent the reuse. [6](#0-5)

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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L147-181)
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

4. **Do not sign with $h = 0$** (the zero message hash).
   This input enables a related algebraic split-view attack in the modified scheme when
   $N_1 > 2t + 1$.
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
