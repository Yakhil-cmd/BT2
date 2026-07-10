### Title
Malicious Coordinator Can Reuse Presignature Across Two Signing Sessions to Extract the Aggregate Secret Key — (`src/ecdsa/robust_ecdsa/sign.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

The robust ECDSA signing protocol enforces `N = 2t+1` and `msg_hash ≠ 0` in code, but provides **no in-protocol mechanism to prevent presignature reuse**. A malicious coordinator can run two signing sessions against the same `PresignOutput` with different `(msg_hash, tweak)` pairs. Because both sessions derive their effective nonce from the same base point `R` via `R' = delta * R`, the two resulting nonces are multiplicatively related and the coordinator — who knows both `delta` values from public parameters — can recover the aggregate secret key via standard ECDSA nonce-reuse algebra.

---

### Finding Description

**Root cause — missing presignature-reuse guard in `sign()`**

`RerandomizedPresignOutput::rerandomize_presign()` derives a per-session scalar:

```
delta = HKDF(entropy, pk, ε, h, R, participants)
R'    = delta · R
alpha'_i = alpha_i / delta
beta'_i  = (beta_i + c_i · ε) / delta
``` [1](#0-0) 

The `sign()` entry-point then accepts the already-rerandomized `presignature: RerandomizedPresignOutput` and enforces only two structural guards: [2](#0-1) 

Neither guard prevents the same raw `PresignOutput` from being rerandomized and signed twice. The `PresignOutput` struct carries no consumed/used flag, and the library exposes no session-ID or nonce-commitment registry.

**Attack path (malicious coordinator)**

The coordinator is a normal participant elected to aggregate shares. It controls which `(msg_hash, tweak, entropy)` tuple it tells each participant to use when calling `rerandomize_presign()`.

1. **Session 1** — coordinator instructs all `2t+1` participants to rerandomize the same `PresignOutput` with `(h₁, ε₁, ρ₁)`, producing `R₁ = δ₁·R`. Participants send shares; coordinator assembles valid signature `(R₁, s₁)`.

2. **Session 2** — coordinator reuses the identical `PresignOutput` with `(h₂, ε₂, ρ₂)`, producing `R₂ = δ₂·R`. Coordinator assembles `(R₂, s₂)`.

3. **Key extraction** — both `δ₁` and `δ₂` are deterministic functions of public inputs (`pk`, `ε`, `h`, `R`, `participants`, `entropy`). The coordinator knows both. The nonces satisfy `R₁ = (δ₁/δ₂)·R₂`, i.e. they are multiplicatively related with a known ratio. Standard ECDSA nonce-reuse algebra then yields the aggregate secret key `x`.

The security documentation explicitly identifies this requirement: [3](#0-2) 

Constraint 3 ("Never reuse a presignature") is stated but **never enforced in code**. Constraints 1 and 4 are enforced; constraint 2 is not enforced either, compounding the risk.

The `RerandomizationArguments` struct — the only place where `(msg_hash, tweak, entropy)` are bound together — is constructed entirely outside the protocol by the caller: [4](#0-3) 

There is no broadcast, commitment, or cross-participant check inside `sign()` or `do_sign_participant()` that would let honest participants detect that the coordinator is feeding them a recycled presignature or mismatched rerandomization inputs. [5](#0-4) 

---

### Impact Explanation

**Critical — extraction of the aggregate secret key.**

Two signing sessions with the same presignature and different `(h, ε)` pairs produce signatures whose nonces are multiplicatively related by a publicly computable ratio `δ₁/δ₂`. This is sufficient for the standard ECDSA nonce-reuse key-recovery attack. The coordinator learns the full aggregate secret `x`, breaking the threshold guarantee entirely: it can subsequently forge arbitrary signatures without any further participant cooperation.

This matches the allowed Critical impact: *"Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets."*

---

### Likelihood Explanation

The coordinator role is reachable by any participant in the signing set (it is chosen per-session, often by the application layer). No external key material, cryptographic break, or out-of-scope assumption is required. The attack needs exactly two signing sessions and one presignature — both are normal protocol operations. The only precondition is that the attacker occupies the coordinator role for both sessions, which is a documented in-scope threat model entry ("malicious coordinator").

---

### Recommendation

1. **Track consumed presignatures.** Assign each `PresignOutput` a unique identifier (e.g., hash of `big_r` concatenated with a session counter). Maintain a per-participant set of used identifiers; reject any `sign()` call that presents an already-consumed identifier.

2. **Bind rerandomization parameters inside the protocol.** Before participants compute their signature shares, have the coordinator broadcast `(big_r, msg_hash, tweak, entropy, participants)` via the existing reliable-broadcast channel. Each participant verifies the broadcast matches the `RerandomizationArguments` it used locally. This enforces constraint 2 from the security documentation in-protocol.

3. **Alternatively, move rerandomization inside `sign()`.** Pass the raw `PresignOutput` plus `RerandomizationArguments` to `sign()` and perform rerandomization inside the protocol after all participants have agreed on the arguments via broadcast. This eliminates the caller-side gap entirely.

---

### Proof of Concept

```rust
// Pseudocode — both sessions use the same `presign_output`

// Session 1: coordinator instructs participants to use (h1, ε1, ρ1)
let args1 = RerandomizationArguments::new(pk, tweak1, h1_bytes, big_r, participants.clone(), entropy1);
let rerand1: Vec<_> = presign_outputs.iter()
    .map(|(p, ps)| (*p, RerandomizedPresignOutput::rerandomize_presign(ps, &args1).unwrap()))
    .collect();
let sig1 = run_sign(rerand1, max_malicious, coordinator, derived_pk1, h1_scalar);
// sig1 = (R1, s1) where R1 = delta1 * R

// Session 2: coordinator reuses the SAME presign_outputs with (h2, ε2, ρ2)
let args2 = RerandomizationArguments::new(pk, tweak2, h2_bytes, big_r, participants.clone(), entropy2);
let rerand2: Vec<_> = presign_outputs.iter()
    .map(|(p, ps)| (*p, RerandomizedPresignOutput::rerandomize_presign(ps, &args2).unwrap()))
    .collect();
let sig2 = run_sign(rerand2, max_malicious, coordinator, derived_pk2, h2_scalar);
// sig2 = (R2, s2) where R2 = delta2 * R

// Key recovery: coordinator knows delta1, delta2 (public inputs → HKDF outputs)
// R1 = (delta1/delta2) * R2  →  nonce-reuse algebra recovers x
let ratio = delta1 * delta2.invert().unwrap();
// standard ECDSA nonce-reuse: x = (s1*h2 - s2*h1) / (r*(s2 - s1*ratio)) mod q
```

The library's `sign()` function accepts both `rerand1` and `rerand2` without complaint because the only guards checked are participant-count and `msg_hash ≠ 0`. [6](#0-5) [1](#0-0)

### Citations

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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L33-108)
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
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    // ensure number of participants during the signing phase is >= 2 * max_malicious + 1
    let robust_ecdsa_threshold = max_malicious
        .into()
        .value()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            InitializationError::BadParameters(
                "2*threshold+1 must be less than usize::MAX".to_string(),
            )
        })?;
    if robust_ecdsa_threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "2*max_malicious+1 must be less than or equals to participant count".to_string(),
        ));
    }

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

    let ctx = Comms::new();
    let fut = fut_wrapper(
        ctx.shared_channel(),
        participants,
        coordinator,
        me,
        public_key,
        presignature,
        msg_hash,
    );
    Ok(make_protocol(ctx, fut))
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

**File:** src/ecdsa/mod.rs (L94-103)
```rust
pub struct RerandomizationArguments {
    // Preferable (but non-binding) the master public key
    pub pk: AffinePoint,
    pub tweak: Tweak,
    pub msg_hash: [u8; 32],
    pub big_r: AffinePoint,
    pub participants: ParticipantList,
    /// Fresh, Unpredictable, and Public source of entropy
    pub entropy: [u8; 32],
}
```
