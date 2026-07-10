### Title
Malicious Coordinator Can Present Different `RerandomizationArguments` to Different Participants, Enabling Secret Key Extraction via Split-View Attack — (`src/ecdsa/robust_ecdsa/sign.rs`, `src/ecdsa/mod.rs`)

---

### Summary

The Robust ECDSA signing protocol accepts a pre-computed `RerandomizedPresignOutput` from each participant without any protocol-level mechanism to verify that all participants used the same `RerandomizationArguments` (i.e., the same `msg_hash`, `tweak`, `participants`, and `entropy`). A malicious coordinator — a reachable, unprivileged role — can distribute different rerandomization contexts to different participants, causing them to compute different rerandomization scalars `delta` from the same presignature. The resulting signature shares, when collected by the coordinator, expose multiplicatively related nonces that allow full secret key recovery via standard ECDSA nonce-reuse techniques.

---

### Finding Description

The Robust ECDSA signing pipeline is split into two caller-driven steps:

**Step 1 — Rerandomization (caller-controlled, outside the protocol):**
Each participant independently calls `RerandomizedPresignOutput::rerandomize_presign(presig, &rerand_args)` with a `RerandomizationArguments` struct that includes `msg_hash: [u8; 32]`, `tweak`, `participants`, `entropy`, and `pk`. The HKDF-derived scalar `delta` is computed from all of these fields. [1](#0-0) [2](#0-1) 

**Step 2 — Signing (protocol-enforced):**
Each participant calls `sign(participants, coordinator, max_malicious, me, public_key, presignature, msg_hash)`. The `presignature` is the already-rerandomized output from Step 1. The `sign()` function enforces `participants.len() == 2*max_malicious+1` and `msg_hash != 0`, but it performs **no check** that the `presignature` was rerandomized with the same `msg_hash`, `tweak`, or `participants` as any other participant. [3](#0-2) 

The `RerandomizedPresignOutput` struct carries no binding to the signing context used during rerandomization: [4](#0-3) 

The security documentation explicitly identifies this gap and states the constraint is left entirely to the caller: [5](#0-4) 

However, the code provides no enforcement mechanism — no commitment, no broadcast, no cross-check — to ensure participants actually satisfy this constraint.

**Attack path:**

1. A malicious coordinator runs presigning with `N = 2t+1` participants `{P1, P2, ..., Pn}`.
2. The coordinator distributes `RerandomizationArguments` to each participant. It sends participant `P_i` arguments with `msg_hash_bytes = H(m1)` and `tweak = ε1`, and sends `P_j` arguments with `msg_hash_bytes = H(m2)` and `tweak = ε2` (different values).
3. `P_i` computes `delta_i = HKDF(..., H(m1), ε1, ...)` and rerandomizes their presignature shares accordingly.
4. `P_j` computes `delta_j = HKDF(..., H(m2), ε2, ...)` — a different scalar — and rerandomizes their shares.
5. Both participants call `sign()` with a consistent `msg_hash` scalar. The `sign()` function accepts both pre-computed `RerandomizedPresignOutput` values without any cross-validation.
6. The coordinator collects `s_i` and `s_j`, which are signature shares derived from the same underlying presignature nonce `k` but rerandomized by different `delta` values. The relationship between these shares satisfies `s_i / s_j = delta_j / delta_i` (modulo the Lagrange and message terms), which — combined with the linearization optimization that pushes computation into presigning — allows the coordinator to recover the secret key.

The documentation confirms this attack is feasible with as few as `2t+2` presigning participants and two signing sessions: [6](#0-5) 

---

### Impact Explanation

**Critical — Extraction of the aggregate secret key.**

The split-view attack recovers the secret key `x` from two signing sessions that use shares derived from the same presignature but rerandomized with different `(h, ε)` inputs. Because the signing protocol's linearization optimization (`s_i = lambda_i * (alpha_i * h + beta_i * Rx + e_i)`) is applied locally by each participant before sending to the coordinator, the coordinator observes shares that are linear functions of the secret with known coefficients. Two such observations with different rerandomization scalars yield a system of equations solvable for `x`.

This matches the allowed Critical impact: **Extraction, reconstruction, or disclosure of private signing shares or aggregate secret material.**

---

### Likelihood Explanation

The coordinator role is not privileged — it is simply one of the `2t+1` participants designated at signing time. Any participant can be the coordinator. The attack requires only that the coordinator distribute different `RerandomizationArguments` to different participants before the signing round, which is a normal part of the coordinator's role (distributing signing parameters). No external assumptions, leaked keys, or cryptographic breaks are required. [7](#0-6) 

---

### Recommendation

Add a protocol round before signing in which each participant broadcasts a commitment (e.g., a hash) to their `RerandomizationArguments` — specifically `(msg_hash_bytes, tweak, participants, entropy)` — and verifies that all other participants committed to the same values before proceeding to compute and send their signature share. Alternatively, include the rerandomization context as a verifiable field inside `RerandomizedPresignOutput` and have the coordinator broadcast it to all participants for cross-verification before the signing round begins.

At minimum, add a runtime assertion inside `sign()` that the `msg_hash` scalar passed to `sign()` is consistent with the `msg_hash` bytes embedded in the `RerandomizedPresignOutput` (which would require storing the rerandomization context in the output struct).

---

### Proof of Concept

```
Setup: N=3, t=1 (so 2t+1=3). Participants: {P1, P2, P3}. Coordinator: P1 (malicious).

1. Run presigning with {P1, P2, P3}. Each participant holds presignature shares
   (big_r, alpha_i, beta_i, c_i, e_i) for the same underlying nonce k.

2. Coordinator P1 constructs two different RerandomizationArguments:
   - args_A: msg_hash=H(m1), tweak=ε1, participants={P1,P2,P3}, entropy=ρ
   - args_B: msg_hash=H(m2), tweak=ε2, participants={P1,P2,P3}, entropy=ρ

3. P1 sends args_A to P2 and args_B to P3.
   - P2 calls rerandomize_presign(presig_2, args_A) → delta_A, rerandomized shares
   - P3 calls rerandomize_presign(presig_3, args_B) → delta_B ≠ delta_A, different rerandomized shares

4. All three participants call sign() with msg_hash=H(m1) and participants={P1,P2,P3}.
   sign() accepts all three RerandomizedPresignOutput values without cross-validation.

5. P2 sends s_2 = lambda_2 * (alpha_2_A * H(m1) + beta_2_A * Rx + e_2) to P1.
   P3 sends s_3 = lambda_3 * (alpha_3_B * H(m1) + beta_3_B * Rx + e_3) to P1.

6. P1 now holds two signature shares derived from the same presignature nonce k
   but with different rerandomization scalars delta_A and delta_B.
   Using the known relationship between alpha_i_A, alpha_i_B (both derived from the
   same presignature alpha_i via different deltas), P1 solves for the secret key x.
``` [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

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

**File:** src/ecdsa/mod.rs (L139-162)
```rust
    pub fn derive_randomness(&self) -> Result<Scalar, ProtocolError> {
        // create a string containing (pk, msg_hash, big_r, sorted(participants))
        let pk_encoded_point = self.pk.to_encoded_point(true);
        let encoded_pk: &[u8] = pk_encoded_point.as_bytes();
        let encoded_tweak: &[u8] = &<Secp256K1ScalarField as Field>::serialize(&self.tweak.value());
        let encoded_msg_hash: &[u8] = &self.msg_hash;
        let big_r_encoded_point = self.big_r.to_encoded_point(true);
        let encoded_big_r: &[u8] = big_r_encoded_point.as_bytes();

        // concatenate all the bytes
        let mut concatenation = Vec::new();
        // 1 byte counter, used in the unlikely case that the hash result is 0
        concatenation.extend_from_slice(&[0u8, 1]);
        concatenation.extend_from_slice(encoded_pk);
        concatenation.extend_from_slice(encoded_tweak);
        concatenation.extend_from_slice(encoded_msg_hash);
        concatenation.extend_from_slice(encoded_big_r);
        // Append each ParticipantId's
        for participant in self.participants.participants() {
            concatenation.extend_from_slice(&participant.bytes());
        }

        // initiate hkdf with the salt and with some `good' entropy
        let hk = Hkdf::<sha3::Sha3_256>::new(Some(&Self::SALT), &self.entropy);
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

**File:** src/ecdsa/robust_ecdsa/mod.rs (L42-52)
```rust
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
