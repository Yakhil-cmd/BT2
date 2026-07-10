### Title
Malicious Coordinator Can Reuse Presignature Across Signing Sessions to Extract Secret Key — (`src/ecdsa/robust_ecdsa/sign.rs`)

---

### Summary

The robust ECDSA `sign()` function accepts a `RerandomizedPresignOutput` without verifying that the `participants` and `msg_hash` passed to it match those used during rerandomization. Because `RerandomizedPresignOutput` does not bind these values, a malicious coordinator can rerandomize the same `PresignOutput` twice with different parameters and run two signing sessions, obtaining two signatures that share the same underlying nonce. This enables secret key extraction via a nonce-reuse attack, as explicitly documented but not enforced in code.

---

### Finding Description

The robust ECDSA signing protocol is split into two phases: presigning (offline) and signing (online). After presigning, the `PresignOutput` is rerandomized using `RerandomizationArguments`, which includes `participants`, `msg_hash`, `tweak`, `big_r`, and `entropy`, to produce a `RerandomizedPresignOutput`. The rerandomization derives a scalar `delta` that shifts the nonce from `k` to `k + delta`.

The `sign()` function in `src/ecdsa/robust_ecdsa/sign.rs` takes `presignature: RerandomizedPresignOutput` and `msg_hash: Scalar` as separate, independent inputs:

```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: impl Into<MaxMalicious>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,  // no binding to participants or msg_hash
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError>
```

The `compute_signature_share` function uses the `participants` list to compute Lagrange coefficients and `msg_hash` to compute the share, but neither value is verified against what was used to create the `RerandomizedPresignOutput`:

```rust
fn compute_signature_share(
    presignature: &RerandomizedPresignOutput,
    msg_hash: Scalar,
    participants: &ParticipantList,
    me: Participant,
) -> Result<SerializableScalar<C>, ProtocolError> {
    let beta = presignature.beta * big_r_x_coordinate + presignature.e;
    let s_me = msg_hash * presignature.alpha + beta;
    let linearized_s_me = s_me * participants.lagrange::<C>(me)?;  // uses caller-supplied participants
    Ok(SerializableScalar::<C>(linearized_s_me))
}
```

The `RerandomizedPresignOutput` struct only stores cryptographic material (`big_r`, `alpha`, `beta`, `e`, `c`) — it does **not** store the `participants` or `msg_hash` used during rerandomization. There is no mechanism in `sign()` to verify consistency.

The documentation in `docs/ecdsa/robust_ecdsa/signing.md` explicitly identifies this as a security requirement but leaves it entirely to the caller:

> *"If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks."*

> *"Moreover, due to protocol modifications relative to [DJNPO20] (notably signature-share linearization), a novel split-view attack exists that can extract the secret key using as few as 2t+2 presigning participants, with as few as two signing sessions."*

The code enforces constraints 1 and 4 from the documentation (N1 = N2 = 2t+1 and msg_hash ≠ 0), but **not** constraints 2 and 3 (parameter agreement and presignature non-reuse):

```rust
// Enforced in code:
if participants.len() != robust_ecdsa_threshold { return Err(...) }  // constraint 1
if bool::from(msg_hash.is_zero()) { return Err(...) }                // constraint 4

// NOT enforced in code:
// - presignature was not previously used                             // constraint 3
// - participants match those used during rerandomization             // constraint 2
// - msg_hash matches that used during rerandomization                // constraint 2
```

---

### Impact Explanation

A malicious coordinator (who is a valid participant — the coordinator role requires no special privilege beyond being in the participant list) can:

1. Complete presigning with participants `{P1, P2, P3}` (t=1, N=3=2t+1), obtaining `PresignOutput` with underlying nonce `k`.
2. Rerandomize `PresignOutput` with `(H1, ε1, entropy1)` → `delta1` → `RerandomizedPresignOutput1` with effective nonce `k + delta1`.
3. Rerandomize the **same** `PresignOutput` with `(H2, ε2, entropy2)` → `delta2` → `RerandomizedPresignOutput2` with effective nonce `k + delta2`.
4. Run signing session 1 with `RerandomizedPresignOutput1` and `msg_hash = H1` → signature `(R1, s1)`.
5. Run signing session 2 with `RerandomizedPresignOutput2` and `msg_hash = H2` → signature `(R2, s2)`.
6. The coordinator knows `delta1`, `delta2`, `H1`, `H2`, `R1`, `R2`, `s1`, `s2`, and the relationship `R = k·G`. Using the linearized share structure (`s_me * lagrange_i`), the coordinator can recover the aggregate secret key `x` from the two signing equations.

This is a **Critical** impact: extraction of the aggregate secret key material.

---

### Likelihood Explanation

The coordinator is any participant in the signing set — there is no privileged access requirement. The attack requires:
- Control of the coordinator role (achievable by any participant in the signing set)
- Ability to run two signing sessions (normal protocol operation)
- Access to the same `PresignOutput` twice (possible since `PresignOutput` is a plain struct with no consumption enforcement)

This is a realistic attack path for any malicious participant who can act as coordinator.

---

### Recommendation

1. **Bind `participants` and `msg_hash` into `RerandomizedPresignOutput`** at rerandomization time, and verify them in `sign()` before proceeding.
2. **Consume `PresignOutput` by value** in the rerandomization function so Rust's ownership system prevents it from being rerandomized twice (and ensure `PresignOutput` does not implement `Clone`).
3. Alternatively, add a **nonce/session-ID commitment** to `RerandomizedPresignOutput` that is verified during signing to ensure each presignature is used at most once.

---

### Proof of Concept

```
// Attacker is coordinator in a 3-party (t=1) signing group

// Step 1: Run presigning normally
let presign_out = run_presigning(participants, me, args, rng);
// presign_out.big_r = k·G for some secret nonce k

// Step 2: Rerandomize TWICE with different parameters
let rerand_args_1 = RerandomizationArguments::new(pk, tweak, H1, presign_out.big_r, participants, entropy1);
let delta1 = rerand_args_1.derive_randomness();
let rerand_presig_1 = rerandomize(presign_out.clone(), delta1);  // clone allows reuse

let rerand_args_2 = RerandomizationArguments::new(pk, tweak, H2, presign_out.big_r, participants, entropy2);
let delta2 = rerand_args_2.derive_randomness();
let rerand_presig_2 = rerandomize(presign_out, delta2);

// Step 3: Run two signing sessions — sign() has no check preventing this
let sig1 = run_sign(participants, coordinator, max_malicious, me, pk, rerand_presig_1, H1);
let sig2 = run_sign(participants, coordinator, max_malicious, me, pk, rerand_presig_2, H2);

// Step 4: Coordinator recovers secret key x from (sig1, sig2, delta1, delta2, H1, H2)
// using the nonce-reuse relationship exposed by signature-share linearization
```

The `sign()` function at lines 86–95 of `src/ecdsa/robust_ecdsa/sign.rs` enforces N=2t+1 and msg_hash≠0 but contains no check binding the presignature to the current session's `participants` or `msg_hash`, making steps 2–4 above reachable without any privileged access. [1](#0-0) [2](#0-1) 
<cite repo="Ellentat/threshold-signatures--002" path="docs/ecd

### Citations

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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L169-184)
```rust
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
```
