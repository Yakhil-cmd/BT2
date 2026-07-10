### Title
Disabled Signature Share Verification Enables Unattributable Permanent Denial of Signing — (`src/frost/eddsa/sign.rs`, `src/frost/redjubjub/sign.rs`)

---

### Summary

Both FROST EdDSA and FROST RedJubjub signing implementations pass an empty `BTreeMap` as `verifying_shares` to `PublicKeyPackage::new()`, disabling per-share verification inside `aggregate()`. This is the direct analog of the external report's pattern: a "safe" wrapper (individual share verification) exists but is deliberately bypassed. A single malicious signing participant can submit a crafted invalid signature share, causing `aggregate()` to fail with no ability to identify or exclude the offending party, enabling permanent, unattributable denial of signing for all honest participants.

---

### Finding Description

In `src/frost/eddsa/sign.rs`, `do_sign_coordinator_v1` and `do_sign_coordinator_v2` both construct the `PublicKeyPackage` with an empty verifying-shares map:

```rust
// src/frost/eddsa/sign.rs lines 160–165
let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package);
let signature = aggregate(&signing_package, &signature_shares, &public_key_package)
    .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
```

The same pattern appears in `src/frost/redjubjub/sign.rs`, `do_sign_coordinator`:

```rust
// src/frost/redjubjub/sign.rs lines 174–184
let pk_package = PublicKeyPackage::new(BTreeMap::new(), keygen_output.public_key);
let signature = aggregate(
    &signing_package,
    &signature_shares,
    &pk_package,
    &randomized_params,
)
.map_err(|_| ProtocolError::ErrorFrostAggregation)?;
```

The FROST `aggregate()` function has two verification layers:
1. **Per-share verification** — each `SignatureShare` is checked against the corresponding `VerifyingShare` stored in `PublicKeyPackage::verifying_shares`.
2. **Final signature verification** — the aggregated signature is verified against the group public key.

By supplying `BTreeMap::new()` as `verifying_shares`, layer 1 is entirely skipped. Only layer 2 runs. When a malicious participant submits an invalid share, layer 2 fails (the aggregated signature is invalid), but the protocol has no information about which share was bad. The coordinator cannot identify or exclude the offending participant.

The code comments acknowledge this explicitly:

> "We supply empty map as `verifying_shares` because we have disabled 'cheater-detection' feature flag. Feature 'cheater-detection' only points to a malicious participant, if there's such. It doesn't bring any additional guarantees."

This reasoning is incorrect with respect to availability: cheater detection does bring an additional guarantee — the ability to attribute failure and recover by excluding the identified malicious party.

---

### Impact Explanation

**High: Permanent denial of signing for honest parties.**

A malicious participant in any FROST EdDSA or FROST RedJubjub signing session can submit a syntactically valid but cryptographically incorrect `SignatureShare`. Because `verifying_shares` is empty, `aggregate()` cannot check individual shares; it only checks the final aggregated result, which fails. The coordinator receives `ProtocolError::ErrorFrostAggregation` (or `AssertionFailed`) with no attribution. The malicious participant is indistinguishable from an honest one. They can repeat this in every signing attempt, permanently blocking signature production for all honest parties without ever being identified or excluded.

---

### Likelihood Explanation

Any participant in the signing protocol is an attacker-controlled entry point. No special privilege is required beyond being included in the signing set. The attack requires only that the participant serialize and send a modified `SignatureShare` scalar. This is trivially reachable by any participant who deviates from the protocol.

---

### Recommendation

Populate `verifying_shares` in `PublicKeyPackage` using the per-participant verifying shares derived from `KeygenOutput`. In `construct_key_package`, `verifying_share` is already computed as `signing_share.into()`. Collect these per-participant verifying shares during the commitment/share-collection rounds and pass them to `PublicKeyPackage::new(verifying_shares_map, vk_package)`. This restores per-share verification inside `aggregate()`, allowing the coordinator to identify and exclude the malicious participant and retry with the remaining honest set.

---

### Proof of Concept

1. Honest participants run `sign_v1` or `sign_v2` (EdDSA) or `sign` (RedJubjub).
2. The malicious participant intercepts the `round2::sign` call and replaces the resulting `SignatureShare` scalar with a random value before sending it to the coordinator.
3. The coordinator collects all shares and calls `aggregate()` with `PublicKeyPackage::new(BTreeMap::new(), vk_package)`.
4. Because `verifying_shares` is empty, `aggregate()` skips per-share checks, sums all shares (including the corrupted one), and attempts final signature verification — which fails.
5. The coordinator returns `ProtocolError::AssertionFailed("signature failed to verify")` or `ProtocolError::ErrorFrostAggregation` with no indication of which participant submitted the bad share.
6. The malicious participant repeats step 2 in every subsequent signing session, permanently denying signing to all honest parties. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/frost/eddsa/sign.rs (L160-165)
```rust
    // We supply empty map as `verifying_shares` because we have disabled "cheater-detection" feature flag.
    // Feature "cheater-detection" only points to a malicious participant, if there's such.
    // It doesn't bring any additional guarantees.
    let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package);
    let signature = aggregate(&signing_package, &signature_shares, &public_key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
```

**File:** src/frost/eddsa/sign.rs (L179-222)
```rust
async fn do_sign_coordinator_v2(
    mut chan: SharedChannel,
    participants: ParticipantList,
    threshold: ReconstructionLowerBound,
    me: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
) -> Result<SignatureOption, ProtocolError> {
    // --- Round 1
    let signing_package =
        frost_ed25519::SigningPackage::new(presignature.commitments_map, message.as_slice());

    let mut signature_shares: BTreeMap<frost_ed25519::Identifier, round2::SignatureShare> =
        BTreeMap::new();

    let vk_package = keygen_output.public_key;

    let key_package =
        construct_key_package(threshold, me, keygen_output.private_share, &vk_package)?;

    let key_package = Zeroizing::new(key_package);
    let signature_share = round2::sign(&signing_package, &presignature.nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
    signature_shares.insert(me.to_identifier()?, signature_share);

    let sign_waitpoint = chan.next_waitpoint();
    for (from, signature_share) in
        recv_from_others(&chan, sign_waitpoint, &participants, me).await?
    {
        signature_shares.insert(from.to_identifier()?, signature_share);
    }

    // --- Signature aggregation.
    // * Converted collected signature shares into the signature.
    // * Signature is verified internally during `aggregate()` call.
    // We supply empty map as `verifying_shares` because we have disabled "cheater-detection" feature flag.
    // Feature "cheater-detection" only points to a malicious participant, if there's such.
    // It doesn't bring any additional guarantees.
    let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package);
    let signature = aggregate(&signing_package, &signature_shares, &public_key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    Ok(Some(signature))
```

**File:** src/frost/redjubjub/sign.rs (L130-186)
```rust
async fn do_sign_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    threshold: ReconstructionLowerBound,
    me: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
    randomizer: Randomizer,
) -> Result<SignatureOption, ProtocolError> {
    // --- Round 1
    let key_package = construct_key_package(threshold, me, &keygen_output)?;
    let key_package = Zeroizing::new(key_package);
    let signing_package = SigningPackage::new(presignature.commitments_map, &message);
    let randomized_params =
        RandomizedParams::from_randomizer(&keygen_output.public_key, randomizer);

    let randomizer = randomized_params.randomizer();
    // Send the Randomizer to everyone
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &randomizer)?;

    // Round 2
    let signature_share = round2::sign(
        &signing_package,
        &presignature.nonces,
        &key_package,
        *randomizer,
    )
    .map_err(|_| ProtocolError::ErrorFrostSigningFailed)?;

    let sign_waitpoint = chan.next_waitpoint();
    let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    signature_shares.insert(me.to_identifier()?, signature_share);
    for (from, signature_share) in
        recv_from_others(&chan, sign_waitpoint, &participants, me).await?
    {
        signature_shares.insert(from.to_identifier()?, signature_share);
    }

    // --- Signature aggregation.
    // * Converted collected signature shares into the signature.
    // * Signature is verified internally during `aggregate()` call.

    // We use empty BTreeMap because "cheater-detection" feature is disabled
    // Feature "cheater-detection" unveils existant malicious participants
    let pk_package = PublicKeyPackage::new(BTreeMap::new(), keygen_output.public_key);

    let signature = aggregate(
        &signing_package,
        &signature_shares,
        &pk_package,
        &randomized_params,
    )
    .map_err(|_| ProtocolError::ErrorFrostAggregation)?;
    Ok(Some(signature))
}
```
