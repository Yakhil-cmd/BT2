### Title
FROST `sign_v1` Participant Does Not Validate Signing Package Commitment Set Against Expected Participant List - (File: `src/frost/eddsa/sign.rs`)

---

### Summary

In `do_sign_participant_v1`, a non-coordinator participant receives a `SigningPackage` from the coordinator and validates only the embedded message, not the signing commitments set. The `participants` list is structurally absent from `do_sign_participant_v1`'s signature, making this validation impossible. A malicious coordinator can send different signing packages — each with a different commitment set — to different participants, causing each honest party to compute its signature share under a different participant set (different Lagrange coefficients, different challenge). This is a split-view attack that corrupts signing outputs.

---

### Finding Description

In `fut_wrapper_v1`, the `participants` list is forwarded to `do_sign_coordinator_v1` but silently dropped when dispatching to the participant path: [1](#0-0) 

`do_sign_participant_v1` therefore has no access to the agreed-upon participant set: [2](#0-1) 

After receiving the signing package from the coordinator, the only check performed is on the message field: [3](#0-2) 

The `signing_package.signing_commitments()` map — which encodes the full participant set and their public nonce commitments — is never validated against the expected `participants` list. The participant then immediately proceeds to compute and send its signature share: [4](#0-3) 

In contrast, `sign_v2` is not affected because each participant uses their own locally-held `presignature.commitments_map` (established during the presign protocol) rather than a package received from the coordinator at signing time: [5](#0-4) 

The FROST security model explicitly requires that all participants see the same signing package. The code enforces the message component of this requirement but not the commitment-set component.

---

### Impact Explanation

A malicious coordinator can present different `SigningPackage` values to different participants — each containing the correct message but a different commitment set (different participant identifiers). Each honest participant passes the message check and computes:

```
z_i = nonce_i + λ_i(P_j) · x_i · c_j
```

where `P_j` and `c_j` differ per participant. The resulting signature shares are computed under inconsistent participant sets with inconsistent Lagrange coefficients and inconsistent challenges. These shares cannot be aggregated into a valid signature. Honest parties have accepted and acted on inconsistent participant sets and transcripts, producing unusable cryptographic outputs.

This maps to: **High — Corruption of sign outputs so honest parties accept inconsistent participant sets, transcripts, or unusable cryptographic outputs.**

---

### Likelihood Explanation

The coordinator role is explicitly within the threat model: the code already validates `signing_package.message()` specifically to guard against a malicious coordinator sending a wrong message. The same coordinator can trivially send a structurally valid package (correct message, correct format, participant's own commitment present so `round2::sign` does not immediately reject it) while substituting other participants' commitments. No cryptographic capability is required — only the ability to craft different `SigningPackage` serializations per recipient, which is a standard coordinator capability.

---

### Recommendation

Pass the `participants: ParticipantList` argument into `do_sign_participant_v1` (mirroring `do_sign_coordinator_v1`) and, after receiving the signing package, validate that the set of identifiers in `signing_package.signing_commitments()` exactly matches the expected participant identifiers. Reject the package if any identifier is missing, extra, or unexpected.

---

### Proof of Concept

1. Coordinator holds the agreed participant set `{A, B, C}`.
2. Coordinator sends to participant A: `SigningPackage::new(commitments_from_{A,B,C}, message)`.
3. Coordinator sends to participant B: `SigningPackage::new(commitments_from_{A,B,D}, message)`.
4. Both A and B pass the message check at line 283 and proceed to `round2::sign`.
5. A computes `z_A` with Lagrange coefficient `λ_A({A,B,C})` and challenge `c({A,B,C})`.
6. B computes `z_B` with Lagrange coefficient `λ_B({A,B,D})` and challenge `c({A,B,D})`.
7. The coordinator collects `z_A` and `z_B` — shares computed under inconsistent participant sets — corrupting the signing transcript. Honest parties have accepted and processed inconsistent participant sets with no error. [6](#0-5)

### Citations

**File:** src/frost/eddsa/sign.rs (L234-242)
```rust
async fn do_sign_participant_v1(
    mut chan: SharedChannel,
    threshold: ReconstructionLowerBound,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: &mut impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
```

**File:** src/frost/eddsa/sign.rs (L272-301)
```rust
    let r2_wait_point = chan.next_waitpoint();
    let signing_package = loop {
        let (from, signing_package): (_, frost_ed25519::SigningPackage) =
            chan.recv(r2_wait_point).await?;
        if from != coordinator {
            continue;
        }
        break signing_package;
    };

    // Step 2.2
    if signing_package.message() != message.as_slice() {
        return Err(ProtocolError::AssertionFailed(
            "Expected message doesn't match with the actual message received in a signing package"
                .to_string(),
        ));
    }

    // Step 2.3
    let vk_package = keygen_output.public_key;
    let key_package = construct_key_package(threshold, me, signing_share, &vk_package)?;
    // Ensures the values are zeroized on drop
    let key_package = Zeroizing::new(key_package);
    let signature_share = round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    // Step 2.4
    chan.send_private(r2_wait_point, coordinator, &signature_share)?;

    Ok(None)
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

**File:** src/frost/eddsa/sign.rs (L372-405)
```rust
async fn fut_wrapper_v1(
    chan: SharedChannel,
    participants: ParticipantList,
    threshold: ReconstructionLowerBound,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    mut rng: impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    if me == coordinator {
        do_sign_coordinator_v1(
            chan,
            participants,
            threshold,
            me,
            keygen_output,
            message,
            &mut rng,
        )
        .await
    } else {
        do_sign_participant_v1(
            chan,
            threshold,
            me,
            coordinator,
            keygen_output,
            message,
            &mut rng,
        )
        .await
    }
}
```
