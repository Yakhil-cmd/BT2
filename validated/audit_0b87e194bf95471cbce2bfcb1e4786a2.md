### Title
Missing Cross-Participant Consistency Check on Rerandomization Inputs Enables Split-View Secret Key Extraction by Malicious Coordinator - (File: `src/ecdsa/robust_ecdsa/sign.rs`, `src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

The `sign()` function in both ECDSA variants accepts a `RerandomizedPresignOutput` without any protocol-level mechanism to verify that all participants rerandomized their presignature shares using the same `(msg_hash, tweak, participants)` inputs. A malicious coordinator can silently present different rerandomization arguments to different participants within the same signing session. Because `RerandomizedPresignOutput` stores no binding context and `sign()` performs no cross-participant consistency check, honest participants have no way to detect the inconsistency. This enables the documented split-view attack, allowing the coordinator to extract the aggregate secret key across two signing sessions.

---

### Finding Description

**Vulnerability class**: Missing context-binding/consistency check (direct analog to the external report's `deadline = block.timestamp` pattern — a protection is nominally described but not enforced in the protocol).

**Root cause in code**:

`RerandomizedPresignOutput` in both variants stores only the rerandomized cryptographic values and carries no record of the `(msg_hash, tweak, participants)` used to derive `delta`:

```rust
// src/ecdsa/robust_ecdsa/mod.rs lines 43-52
pub struct RerandomizedPresignOutput {
    big_r: AffinePoint,
    e: Scalar,
    alpha: Scalar,
    beta: Scalar,
    // NO stored msg_hash, tweak, or participants
}
``` [1](#0-0) 

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs lines 54-63
pub struct RerandomizedPresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,
    pub sigma: Scalar,
    // NO stored msg_hash, tweak, or participants
}
``` [2](#0-1) 

The `sign()` function in `robust_ecdsa/sign.rs` accepts `presignature: RerandomizedPresignOutput` and `msg_hash: Scalar` as independent inputs with no check that `msg_hash` matches what was used to compute `delta` inside `rerandomize_presign()`: [3](#0-2) 

The `compute_signature_share` function uses `msg_hash` directly against the already-rerandomized `alpha`, `beta`, `e` without any binding verification: [4](#0-3) 

The security documentation explicitly identifies this as a required constraint but delegates it entirely to the caller with no enforcement in the protocol: [5](#0-4) 

**Exploit flow**:

1. A malicious coordinator holds a presignature `P` and the participant set `{P1, P2, ..., P_{2t+1}}`.
2. **Session 1**: Coordinator calls `rerandomize_presign(P, args_A)` with `args_A = (h_A, epsilon_A, participants)` for participant P1, and `rerandomize_presign(P, args_B)` with `args_B = (h_B, epsilon_B, participants)` for participant P2 (and so on for others). All participants are told to call `sign()` with the same `msg_hash = h_A`. P1's presignature is consistent; P2's is not — P2's `alpha`, `beta`, `Rx` were derived from `delta_B ≠ delta_A`. P2 has no way to detect this.
3. Each participant independently calls `sign()` with their (inconsistently rerandomized) presignature and `h_A`. The coordinator collects all `s_i` shares.
4. **Session 2**: Coordinator repeats with a fresh presignature and different inconsistent inputs.
5. The coordinator now has two sets of signature-share equations involving multiplicatively related nonces, enabling standard ECDSA nonce-reuse key extraction as documented. [6](#0-5) 

The `N1 = N2 = 2t+1` enforcement in `sign()` prevents two non-overlapping quorums from reusing a presignature across sessions, but it does **not** prevent a malicious coordinator from presenting inconsistent rerandomization inputs to different participants **within** a single session: [7](#0-6) 

---

### Impact Explanation

**Critical**: A malicious coordinator can extract the aggregate secret key. The split-view attack documented in `docs/ecdsa/robust_ecdsa/signing.md` (lines 156–158) states that key extraction is possible with as few as `2t+2` presigning participants and two signing sessions. The missing check is the exact mechanism that makes this attack reachable: honest participants contribute signature shares computed under inconsistent nonce material without any protocol-level warning. [8](#0-7) 

This maps directly to the allowed Critical impact: **Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, or nonce material**.

---

### Likelihood Explanation

The coordinator role is reachable by any participant — it requires no privileged access. The attack requires only that the coordinator compute two different `RerandomizedPresignOutput` values from the same `PresignOutput` (trivially possible since `rerandomize_presign` is a pure function) and distribute them to different participants. No cryptographic primitive break is needed. The library's own documentation acknowledges this attack vector and the required mitigation, confirming the attack is realistic and the mitigation is absent from the protocol itself. [9](#0-8) 

---

### Recommendation

Add a protocol round before participants contribute signature shares in which each participant broadcasts a commitment to their rerandomization inputs `(msg_hash, tweak, participants, big_r)`. Each participant must verify that all other participants committed to the same values before computing and sending their `s_i`. This is the standard approach for ensuring consistent views in multi-party protocols and directly closes the split-view attack vector.

Concretely, `RerandomizedPresignOutput` should store a binding commitment (e.g., a hash of `(msg_hash, tweak, participants, big_r)`) and `sign()` should include a broadcast-and-verify round where participants exchange and check these commitments before proceeding. [10](#0-9) 

---

### Proof of Concept

**Setup**: `t = 1`, so `N = 2t+1 = 3` participants `{P1, P2, P3}`. Coordinator is P1.

1. Run presigning to obtain `PresignOutput P` with `big_r = R`.
2. **Session 1**:
   - Coordinator computes `RP1 = rerandomize_presign(P, args(h_real, eps_real, {P1,P2,P3}))` → sends to P1.
   - Coordinator computes `RP2 = rerandomize_presign(P, args(h_fake, eps_fake, {P1,P2,P3}))` → sends to P2.
   - Coordinator computes `RP3 = rerandomize_presign(P, args(h_fake2, eps_fake2, {P1,P2,P3}))` → sends to P3.
   - All participants are told `msg_hash = h_real`. Each calls `sign(..., RPi, h_real)`.
   - P2 and P3 compute `s_i` using `h_real` but nonce material derived from `h_fake`/`h_fake2`. No error is raised.
   - Coordinator collects `s_1, s_2, s_3` — three equations in the secret shares.
3. **Session 2**: Repeat with a fresh presignature and different inconsistent inputs. Coordinator collects three more equations.
4. Coordinator solves the system of equations to recover the secret key shares, as described in the split-view attack analysis. [11](#0-10) [12](#0-11)

### Citations

**File:** src/ecdsa/robust_ecdsa/mod.rs (L43-52)
```rust
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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L24-32)
```rust
/// WARNING:
/// This robust ECDSA scheme is vulnerable to split-view attacks in the robust
/// setting if different subsets of participants sign different `(msg_hash, tweak)`
/// values using shares derived from the same presignature (i.e., different
/// rerandomization inputs for the same presignature).
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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L110-124)
```rust
/// Performs signing from any participant's perspective (except the coordinator)
fn do_sign_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    presignature: &RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    let s_me = compute_signature_share(presignature, msg_hash, participants, me)?;
    let wait_round = chan.next_waitpoint();
    chan.send_private(wait_round, coordinator, &s_me)?;

    Ok(None)
}
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L168-185)
```rust
/// A common computation done by both the coordinator and the other participants
fn compute_signature_share(
    presignature: &RerandomizedPresignOutput,
    msg_hash: Scalar,
    participants: &ParticipantList,
    me: Participant,
) -> Result<SerializableScalar<C>, ProtocolError> {
    // (beta_i + tweak * k_i) * delta^{-1}
    let big_r = presignature.big_r;
    let big_r_x_coordinate = x_coordinate(&big_r);
    // beta * Rx + e
    let beta = presignature.beta * big_r_x_coordinate + presignature.e;

    let s_me = msg_hash * presignature.alpha + beta;
    // lambda_i * s_i
    let linearized_s_me = s_me * participants.lagrange::<C>(me)?;
    Ok(SerializableScalar::<C>(linearized_s_me))
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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L160-174)
```markdown
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
```
