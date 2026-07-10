### Title
Coordinator-Exclusive Output Delivery Enables Permanent Denial of Signing and CKD for Honest Participants — (`src/ecdsa/ot_based_ecdsa/sign.rs`, `src/ecdsa/robust_ecdsa/sign.rs`, `src/frost/eddsa/sign.rs`, `src/frost/redjubjub/sign.rs`, `src/confidential_key_derivation/protocol.rs`)

---

### Summary

Across every signing and CKD protocol in this library, non-coordinator participants contribute their secret shares to the coordinator and unconditionally return `Ok(None)`. The coordinator is the sole entity that receives `Ok(Some(output))`. The coordinator never broadcasts the final aggregated result back to participants within the protocol. A malicious participant who is designated as coordinator can collect all signature shares (or CKD shares), permanently consume the presignature material, and withhold the final output — permanently denying the signing session to all honest parties with no recourse within the protocol.

---

### Finding Description

In every signing and CKD protocol, the output is structurally gated to the coordinator only. Non-coordinator participants send their secret shares privately to the coordinator and immediately return `Ok(None)`:

**OT-based ECDSA** (`src/ecdsa/ot_based_ecdsa/sign.rs`): [1](#0-0) 

**Robust ECDSA** (`src/ecdsa/robust_ecdsa/sign.rs`): [2](#0-1) 

**FROST EdDSA v2** (`src/frost/eddsa/sign.rs`): [3](#0-2) 

**CKD** (`src/confidential_key_derivation/protocol.rs`): [4](#0-3) 

The coordinator path, by contrast, aggregates all received shares and returns `Ok(Some(...))`: [5](#0-4) [6](#0-5) 

The dispatch logic in every protocol confirms this asymmetry — only `me == coordinator` ever produces a `Some` output: [7](#0-6) [8](#0-7) 

There is no step in any of these protocols where the coordinator sends the final aggregated signature or CKD output back to participants. Participants have no independent path to reconstruct the output — they hold only their own share `s_i`, not the full sum `s = Σ s_j`.

The coordinator role is not a trusted role by design. The security documentation explicitly treats the coordinator as a potential adversary:

> "The coordinator must not be able to present different message hashes, tweaks, or participant lists to different signers." [9](#0-8) 

---

### Impact Explanation

**High — Permanent denial of signing/CKD for honest parties.**

When a malicious coordinator executes the attack:

1. All honest participants compute their signature share `s_i` using their presignature material (nonces `k_i`, `sigma_i` or FROST nonces).
2. They send `s_i` privately to the coordinator and return `Ok(None)` — their protocol execution is complete and their presignature material is consumed.
3. The coordinator collects all shares but never produces or distributes the final signature.
4. The presignature is permanently consumed. Per the library's own security requirements, presignatures **must never be reused** — even across failed or aborted sessions.
5. Honest participants are permanently denied the signing output for that session. They must run a full new offline presign phase (expensive) before they can attempt to sign again.

For the CKD protocol, the coordinator receives all participants' `(norm_big_y, norm_big_c)` shares and is the only entity that computes `CKDOutput`. If the coordinator withholds it, the CKD session is permanently denied and participants must re-run the protocol with a new coordinator. [10](#0-9) 

---

### Likelihood Explanation

**High.** The coordinator is simply a `Participant` value passed as a parameter — any participant in the signing set can be designated coordinator. No privileged key or external access is required. A malicious participant who is chosen as coordinator can execute this attack in a single protocol run by completing their own share computation, collecting all other shares via the normal protocol channel, and then simply not producing the output. The attack requires no cryptographic break and is trivially reachable from the normal library API. [11](#0-10) 

---

### Recommendation

After the coordinator aggregates the final output, it should broadcast the result back to all participants over the shared channel before the protocol terminates. Each participant should verify the broadcast signature against the known public key before accepting it. This mirrors the pattern already used in FROST v1 signing, where the coordinator broadcasts the `SigningPackage` to all participants in round 2: [12](#0-11) 

Applying the same broadcast-and-verify pattern to the final aggregated signature in all protocols would ensure that every honest participant receives and can independently verify the output, eliminating the coordinator's unilateral ability to deny the result.

---

### Proof of Concept

```
Setup: 3 participants P1 (coordinator), P2, P3. Threshold = 2.

1. All three call `sign(participants, coordinator=P1, me=Pi, ...)`.
2. P2 and P3 each compute s_i and call:
       chan.send_private(wait0, coordinator, &s_i)
   then return Ok(None) — their presignature material is now consumed.
3. P1 (malicious coordinator) receives s_2 and s_3 via recv_from_others,
   computes the full signature s = s_1 + s_2 + s_3, verifies it internally,
   but simply drops the result instead of distributing it.
4. P2 and P3 have no further protocol steps. Their protocol futures have
   already resolved to Ok(None).
5. The presignature nonces used by P2 and P3 are consumed and cannot be
   reused. P2 and P3 must run a new offline presign phase.
6. The signing session is permanently failed for all honest participants.
   P1 alone holds the valid signature.
```

The attack path is directly reachable through the public `sign()` API with no privileged access required. [13](#0-12) [14](#0-13)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L22-55)
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
    let threshold = usize::from(threshold.into());
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
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L79-95)
```rust
fn do_sign_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    presignature: &RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    // Round 1
    let s_i = compute_signature_share(participants, me, presignature, msg_hash)?;
    // Send si
    // Spec 1.4
    let wait0 = chan.next_waitpoint();
    chan.send_private(wait0, coordinator, &s_i)?;

    Ok(None)
}
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L97-136)
```rust
/// Performs signing from only the coordinator's perspective
async fn do_sign_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    // Round 1
    let s_i = compute_signature_share(&participants, me, &presignature, msg_hash)?;
    // Spec 1.4 is non-existent for a coordinator

    let wait0 = chan.next_waitpoint();
    // Receive sj
    // Spec 1.5
    let mut s = s_i;
    for (_, s_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
        // Spec 1.6
        s += s_j;
    }

    // Normalize s
    // Spec 1.7
    s.conditional_assign(&(-s), s.is_high());

    let sig = Signature {
        big_r: presignature.big_r,
        s,
    };

    // Spec 1.8
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    Ok(Some(sig))
}
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L162-183)
```rust
async fn fut_wrapper(
    chan: SharedChannel,
    participants: ParticipantList,
    coordinator: Participant,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    if me == coordinator {
        do_sign_coordinator(chan, participants, me, public_key, presignature, msg_hash).await
    } else {
        do_sign_participant(
            chan,
            &participants,
            coordinator,
            me,
            &presignature,
            msg_hash,
        )
    }
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

**File:** src/frost/eddsa/sign.rs (L135-138)
```rust
    // Step 1.5
    let r2_wait_point = chan.next_waitpoint();
    chan.send_many(r2_wait_point, &signing_package)?;

```

**File:** src/frost/eddsa/sign.rs (L313-347)
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
}
```

**File:** src/confidential_key_derivation/protocol.rs (L17-33)
```rust
fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}
```

**File:** src/confidential_key_derivation/protocol.rs (L35-58)
```rust
async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    // Receive everyone's inputs and add them together
    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}
```

**File:** src/confidential_key_derivation/protocol.rs (L119-146)
```rust
/// Depending on whether the current participant is a coordinator or not,
/// runs the ckd protocol as either a participant or a coordinator.
#[allow(clippy::too_many_arguments)]
async fn run_ckd_protocol(
    chan: SharedChannel,
    coordinator: Participant,
    me: Participant,
    participants: ParticipantList,
    key_pair: KeygenOutput,
    app_id: AppId,
    app_pk: PublicKey,
    mut rng: impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    if me == coordinator {
        do_ckd_coordinator(chan, participants, me, &key_pair, &app_id, app_pk, &mut rng).await
    } else {
        do_ckd_participant(
            chan,
            &participants,
            coordinator,
            me,
            &key_pair,
            &app_id,
            app_pk,
            &mut rng,
        )
    }
}
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L170-174)
```markdown
   signing sessions.

2. **Ensure all participants agree on $(h, \epsilon)$ and the signing set.**
   The coordinator must not be able to present different message hashes, tweaks, or
   participant lists to different signers.
```
