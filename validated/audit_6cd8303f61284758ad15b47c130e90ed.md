### Title
Incomplete Split-View Attack Mitigation in Robust ECDSA Allows Secret Key Extraction via Presignature Reuse — (File: `src/ecdsa/robust_ecdsa/sign.rs`, `src/ecdsa/robust_ecdsa/presign.rs`)

---

### Summary

The robust ECDSA implementation partially mitigates split-view attacks by enforcing `N1 = N2 = 2t+1` participants and rejecting `msg_hash = 0`. However, it does not enforce the remaining two security constraints documented in `docs/ecdsa/robust_ecdsa/signing.md`: (1) that a presignature is never reused across signing sessions, and (2) that all participants agree on `(h, ε)` and the signing set. A malicious coordinator — an explicitly in-scope attacker — can reuse the same `PresignOutput` across two signing sessions with different `(h, ε)` values, obtaining two signatures with multiplicatively related nonces, enabling full secret key extraction.

---

### Finding Description

The security considerations in `docs/ecdsa/robust_ecdsa/signing.md` enumerate four constraints required to prevent split-view and presignature-reuse attacks:

1. **Use exactly `N1 = N2 = 2t+1` participants** — enforced in code.
2. **Ensure all participants agree on `(h, ε)` and the signing set** — NOT enforced in code.
3. **Never reuse a presignature** — NOT enforced in code.
4. **Do not sign with `h = 0`** — enforced in code.

The `presign()` function in `src/ecdsa/robust_ecdsa/presign.rs` enforces `participants.len() == 2*max_malicious+1`: [1](#0-0) 

The `sign()` function in `src/ecdsa/robust_ecdsa/sign.rs` enforces the same constraint and rejects `msg_hash == 0`: [2](#0-1) 

However, `sign()` accepts any `RerandomizedPresignOutput` without any binding to a specific session, without verifying it has not been used before, and without verifying that the participants who produced the presignature match the current signing set: [3](#0-2) 

The `RerandomizedPresignOutput` is computed outside `sign()` via `RerandomizedPresignOutput::rerandomize_presign(presig, &rerand_args)`, where `rerand_args` contains `(public_key, tweak, msg_hash, big_r, participants, entropy)`. The coordinator controls all of these inputs and can supply different `(h, ε, ρ)` tuples to the same participants for two separate signing sessions backed by the same underlying `PresignOutput`.

The documentation explicitly acknowledges this residual attack surface:

> If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks. [4](#0-3) 

The `N1 = N2 = 2t+1` enforcement prevents the "different subsets" variant of this attack, but it does **not** prevent the same `2t+1` participants from being asked to sign twice with the same presignature and different `(h, ε)`. The library provides no session token, no presignature consumption flag, and no cross-session binding to detect or prevent this.

---

### Impact Explanation

**Critical — Extraction of the aggregate secret signing key.**

A malicious coordinator executes two signing sessions backed by the same `PresignOutput`:

- Session 1: rerandomize with `(h1, ε1, ρ1)` → `δ1 = HKDF(Y, ε1, h1, R, ρ1)`, `R1 = R^δ1`, collect `s1`.
- Session 2: rerandomize with `(h2, ε2, ρ2)` → `δ2 = HKDF(Y, ε2, h2, R, ρ2)`, `R2 = R^δ2`, collect `s2`.

Both signatures share the same underlying nonce `k` (from the presignature). The nonces are multiplicatively related: `R1 = R^δ1`, `R2 = R^δ2`. From the two signature equations the coordinator can solve for the master secret key `x`. This is the exact attack class described in the security considerations and confirmed by the referenced paper [GS21].

---

### Likelihood Explanation

**High.** The malicious coordinator is an explicitly in-scope attacker profile. The coordinator controls the `RerandomizationArguments` supplied to each participant (including `msg_hash`, `tweak`, `entropy`). Honest participants have no way to detect that the `RerandomizedPresignOutput` they receive is derived from a previously used presignature. The library enforces `N1 = N2 = 2t+1`, which prevents the "disjoint-subset" variant of the attack, but this enforcement creates a false sense of completeness: users who see the `N1 = N2 = 2t+1` and `h ≠ 0` guards in the source may reasonably believe split-view attacks are fully mitigated, when in fact presignature reuse remains exploitable.

---

### Recommendation

1. **Bind presignatures to a single session at the library level.** Include a cryptographic session identifier (e.g., a hash of `(big_r, participants, entropy)`) inside `RerandomizedPresignOutput` and have `sign()` verify it matches the current session parameters. This prevents the coordinator from reusing a presignature with different `(h, ε)`.

2. **Enforce presignature single-use via a consumption token.** Require callers to pass a one-time token (e.g., a nonce or a monotonic counter commitment) that is consumed by `sign()`, making reuse detectable.

3. **At minimum, document the incomplete mitigation prominently in the `sign()` and `presign()` API docstrings**, not only in the separate `docs/` file, so that library consumers are not misled by the presence of the `N1 = N2 = 2t+1` and `h ≠ 0` guards into believing split-view attacks are fully prevented.

---

### Proof of Concept

**Attacker:** Malicious coordinator `C` with no privileged key material.

**Setup:** `t = 2`, `N = 5` participants `{P1, P2, P3, P4, P5}`.

1. `C` orchestrates `presign()` with all 5 participants. Each `Pi` receives `PresignOutput_i = (big_r, alpha_i, beta_i, c_i, e_i)`. [5](#0-4) 

2. `C` constructs `rerand_args1 = (Y, ε1, h1, R, {P1..P5}, ρ1)` and distributes to all participants. Each `Pi` calls `RerandomizedPresignOutput::rerandomize_presign(presig_i, &rerand_args1)` and then `sign(...)`. `C` collects all `s_i^1` and assembles valid signature `(R1, s1)` for message `h1`.

3. `C` constructs `rerand_args2 = (Y, ε2, h2, R, {P1..P5}, ρ2)` (same underlying `PresignOutput`, different `h2 ≠ h1`). Each `Pi` has no record of prior use and calls `sign(...)` again. `C` collects all `s_i^2` and assembles valid signature `(R2, s2)` for message `h2`. [6](#0-5) 

4. `C` now holds `(R1, s1, h1)` and `(R2, s2, h2)` where `R1 = R^δ1`, `R2 = R^δ2`, and both share the same underlying nonce `k`. Using the multiplicatively related nonce relationship documented in the security considerations, `C` recovers the master secret key `x`. [7](#0-6) 

The `sign()` function performs no check that prevents step 3 from succeeding. The `N1 = N2 = 2t+1` guard (line 86) passes because the same 5 participants are used. The `h ≠ 0` guard (line 91) passes because `h2 ≠ 0`. No other guard exists.

### Citations

**File:** src/ecdsa/robust_ecdsa/presign.rs (L30-84)
```rust
pub fn presign(
    participants: &[Participant],
    me: Participant,
    args: PresignArguments,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    if args.max_malicious.value() > participants.len() {
        return Err(InitializationError::BadParameters(
            "max_malicious must be less than or equals to participant count".to_string(),
        ));
    }

    let robust_ecdsa_threshold = args
        .max_malicious
        .value()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            InitializationError::BadParameters(
                "2*max_malicious+1 must be less than usize::MAX".to_string(),
            )
        })?;
    if robust_ecdsa_threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "2*max_malicious+1 must be less than or equals to participant count".to_string(),
        ));
    }

    // To prevent split-view attacks documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during presigning must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }

    let ctx = Comms::new();
    let fut = do_presign(ctx.shared_channel(), participants, me, args, rng);
    Ok(make_protocol(ctx, fut))
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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L149-170)
```markdown
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
```
