### Title
`PresignOutput` Derives `Clone`, Enabling Nonce Reuse and Private Key Share Extraction After Failed Signing Sessions - (File: `src/frost/mod.rs`, `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

### Summary
All three signing schemes expose `PresignOutput` types that derive `Clone`, making it trivially possible to duplicate one-time-use presignature material (nonces and secret shares). If a signing session fails or is aborted by a malicious coordinator, a participant can retry with the same presignature. In FROST (EdDSA/RedJubjub), this directly enables recovery of the participant's private key share via standard nonce-reuse algebra. The library documentation explicitly warns that presignatures must never be reused, yet the `Clone` derive directly contradicts this requirement at the type level.

### Finding Description

**Root cause — `Clone` on secret one-time-use material:**

`PresignOutput<C>` in `src/frost/mod.rs` derives `Clone`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PresignOutput<C: Ciphersuite + Send + 'static> {
    pub nonces: SigningNonces<C>,
    pub commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>>,
}
``` [1](#0-0) 

The `nonces: SigningNonces<C>` field contains the participant's one-time-use hiding and binding nonces. These must never be reused across signing sessions.

The same issue exists in OT-based ECDSA:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,      // nonce share
    pub sigma: Scalar,
}
``` [2](#0-1) 

And in robust ECDSA:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}
``` [3](#0-2) 

The library's own documentation explicitly warns against reuse: [4](#0-3) [5](#0-4) 

The orchestration docs reinforce this: "It's **critical** that the output is then destroyed, so that no other group of parties attempts to re-use that output." [6](#0-5) 

**Attack path (FROST, malicious coordinator):**

The signing v2 path (`do_sign_participant_v2`) takes `presignature: PresignOutput` by value — consuming it in memory. However, because `PresignOutput` is `Clone`, any application that stores presignatures for reliability (database, retry queue) will naturally clone them before passing them in. [7](#0-6) 

1. Participant P generates `presign_output` via `presign()`.
2. Application stores a clone: `let presign_backup = presign_output.clone()`.
3. Malicious coordinator initiates signing session with message M; P uses `presign_output` (consumed in-memory).
4. Coordinator deliberately aborts without completing aggregation (e.g., never sends the signing package, or sends a wrong message to trigger `ProtocolError`).
5. P's application retries with `presign_backup` for a new session — now with message M'.
6. Coordinator holds signature shares `(s_i for M, s_i' for M')` computed with the same nonces.

**Nonce-reuse algebra (FROST):**

The FROST signature share is:
```
s_i = nonce_i + ρ_i * nonce_i' + λ_i * c * secret_i
```
where `ρ_i` (binding factor) and `c` (challenge) both depend on the message. With two sessions using the same `(nonce_i, nonce_i')` but different messages:
```
s_i  - s_i' = (ρ_i - ρ_i') * nonce_i' + λ_i * (c - c') * secret_i
```
All quantities except `secret_i` are known to the coordinator, so `secret_i` (the private key share) is directly recoverable. [8](#0-7) 

### Impact Explanation

**Critical — Extraction of private signing shares.** A malicious coordinator who can observe two FROST signature shares produced with the same nonces but different messages can algebraically recover the participant's private key share `secret_i`. With enough shares (≥ threshold), the full aggregate secret key is reconstructed, enabling unauthorized creation of valid threshold signatures for any message.

### Likelihood Explanation

The `Clone` derive is part of the public API and is required for `Serialize`/`Deserialize` round-trips in practice. Any production deployment that:
- persists presignatures to disk or a database for fault tolerance, or
- implements retry logic after network failures,

will clone presignatures. A malicious coordinator can deliberately trigger retries by aborting sessions at will — no cryptographic capability is required. The coordinator role is reachable without privileged assumptions in the documented threat model. [9](#0-8) 

### Recommendation

Remove `Clone` from `PresignOutput` in all three schemes to enforce single-use at the Rust type level. If serialization for storage is required, provide explicit `to_bytes`/`from_bytes` methods accompanied by prominent security warnings, rather than deriving `Clone` + `Serialize` + `Deserialize` together. Optionally, wrap the nonce material in a newtype that implements `Drop` with zeroization and does not implement `Clone`, making accidental reuse a compile-time error.

### Proof of Concept

```rust
// Participant generates presignature
let presign_out = run_presign_protocol(...);

// Application clones for "retry safety" — enabled by Clone derive
let presign_backup = presign_out.clone();

// Session 1: coordinator sends message M, then aborts
let _ = run_sign_v2(presign_out, message_m, ...); // returns Err(...)

// Session 2: participant retries with backup — same nonces, different message
let sig_share_2 = run_sign_v2(presign_backup, message_m_prime, ...);

// Malicious coordinator now holds sig_share_1 (from session 1, before abort)
// and sig_share_2 (from session 2) — both computed with identical nonces.
// Standard nonce-reuse algebra recovers secret_i.
``` [1](#0-0) [10](#0-9)

### Citations

**File:** src/frost/mod.rs (L36-41)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PresignOutput<C: Ciphersuite + Send + 'static> {
    /// The public nonce commitment.
    pub nonces: SigningNonces<C>,
    pub commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>>,
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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L17-19)
```rust
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L27-29)
```rust
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L70-72)
```markdown
It's **critical** that the output is then destroyed, so that no other
group of parties attempts to re-use that output for another phase.
In particular, the parties need some way of agreeing on which
```

**File:** src/frost/eddsa/sign.rs (L313-346)
```rust
fn do_sign_participant_v2(
    mut chan: SharedChannel,
    threshold: ReconstructionLowerBound,
    me: Participant,
    coordinator: Participant,
    keygen_output: &KeygenOutput,
    presignature: PresignOutput,
    message: &[u8],
) -> Result<SignatureOption, ProtocolError> {
    // --- Round 1.
    // * Send our signature share.
    if coordinator == me {
        return Err(ProtocolError::AssertionFailed(
            "the do_sign_participant function cannot be called
            for a coordinator"
                .to_string(),
        ));
    }

    let vk_package = keygen_output.public_key;

    let key_package =
        construct_key_package(threshold, me, keygen_output.private_share, &vk_package)?;
    // Ensures the values are zeroized on drop
    let key_package = Zeroizing::new(key_package);

    let signing_package = SigningPackage::new(presignature.commitments_map, message);
    let signature_share = round2::sign(&signing_package, &presignature.nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    let sign_waitpoint = chan.next_waitpoint();
    chan.send_private(sign_waitpoint, coordinator, &signature_share)?;

    Ok(None)
```

**File:** docs/eddsa/signing.md (L70-92)
```markdown
* $\blacktriangle$ Assert that $(i, A_i, B_i) \in \mathit{commits}$.
* Compute the hash $h\gets H_4(m)$.
* Compute the multiple hashes for all $j\in\set{1.. N_1}$:

$$
\rho_j \gets H_1(X, h, \mathit{commits}, j)
$$

* Compute the following group commitment

$$
R\gets \sum_j (A_j+ \rho_j \cdot B_j)
$$

* Compute the following challenge:

$$
c\gets H_2(R, X, m)
$$

* Compute the following signature share:

$$
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-177)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.
```
