### Title
Single Malicious Signing Participant Can Abort the Entire FROST Signing Session - (`src/frost/eddsa/sign.rs`)

### Summary

The FROST EdDSA signing coordinator (`do_sign_coordinator_v1` / `do_sign_coordinator_v2`) unconditionally collects signature shares from **all** participants before aggregating, rather than stopping at threshold-many valid shares. A single malicious participant can abort the entire signing session by sending a malformed or cryptographically invalid signature share, even when threshold-many honest participants have already provided valid shares. This is the direct analog of the external report's `_settle()` revert pattern: one failing party propagates a fatal error that blocks all honest parties.

---

### Finding Description

In `do_sign_coordinator_v1` (and identically in `do_sign_coordinator_v2`), the coordinator executes the following sequence:

**Round 1 — collect commitments from ALL participants:** [1](#0-0) 

**Round 2 — collect signature shares from ALL participants:** [2](#0-1) 

**Aggregation — fails if any single share is invalid:** [3](#0-2) 

The helper `recv_from_others` waits until **every** participant in the list has sent a message: [4](#0-3) 

Two distinct attack paths exist:

**Path A — Deserialization abort.** If the malicious participant sends a byte sequence that cannot be deserialized as `round2::SignatureShare`, `chan.recv()` returns `ProtocolError::DeserializationError`: [5](#0-4) 

The `?` operator in `recv_from_others` immediately propagates this error, aborting the coordinator's future before any aggregation occurs.

**Path B — Aggregation abort.** If the malicious participant sends a well-formed but cryptographically invalid share, it is silently inserted into `signature_shares`. Because cheater-detection is explicitly disabled (empty `verifying_shares` map), no per-share verification is performed: [3](#0-2) 

The `aggregate()` call internally verifies the final aggregate signature against the group public key. With one bad share the sum is wrong, the verification fails, and `aggregate()` returns an error that aborts the session.

In both paths the error is fatal and unrecoverable within the current session. The signing package was already constructed with **all** participants' commitments: [6](#0-5) 

so there is no in-session mechanism to drop the malicious participant and re-aggregate from the remaining honest shares.

The same structural pattern exists in `do_sign_coordinator_v2`: [7](#0-6) 

---

### Impact Explanation

**High — Permanent denial of signing for honest parties.**

Any single participant in the signing set can repeatedly abort every signing session. Because the signing package binds all committed participants, honest parties cannot exclude the malicious participant mid-session; they must restart with a different participant list. If the malicious participant is always included (e.g., it is a required signer or the coordinator cannot distinguish it from an honest slow participant), signing is permanently denied. This matches the allowed impact: *"Permanent denial of signing … for honest parties under valid protocol inputs and documented trust assumptions."*

---

### Likelihood Explanation

**High.** The attack requires no special privilege. Any participant who has been admitted to the signing session (i.e., whose commitment was accepted in Round 1) can execute it by sending one malformed byte string in Round 2. No cryptographic material needs to be compromised. The attack is repeatable across every signing attempt.

---

### Recommendation

1. **Collect only threshold-many shares.** Stop `recv_from_others` as soon as `threshold` valid shares have been received. This requires restructuring Round 1 so the signing package is built from only the threshold-many participants whose shares will actually be used.

2. **Isolate per-participant deserialization errors.** In `recv_from_others`, catch deserialization failures per message and skip the offending participant rather than propagating the error to the caller. Track which participants failed and surface them as identified misbehaving parties.

3. **Enable cheater detection.** Populate `verifying_shares` in `PublicKeyPackage` so that `aggregate()` can identify which specific share is invalid, enabling the coordinator to exclude that participant and retry with the remaining honest shares.

---

### Proof of Concept

```
Setup: n=5 participants, threshold t=3. Participants: P1 (coordinator), P2, P3, P4 (honest), P5 (malicious).

Round 1:
  - All 5 participants send valid commitments to P1.
  - P1 builds signing_package with all 5 commitments.
  - P1 broadcasts signing_package to all.

Round 2:
  - P2, P3, P4 send valid signature shares to P1.
  - P5 sends 16 random bytes (malformed share) to P1.

Coordinator (P1) in recv_from_others:
  - Receives P2's share → ok
  - Receives P3's share → ok
  - Receives P4's share → ok
  - Receives P5's garbage → chan.recv::<round2::SignatureShare>() fails deserialization
  - recv_from_others returns Err(ProtocolError::DeserializationError(...))
  - do_sign_coordinator_v1 returns Err(...)

Result: Signing session aborted. P2, P3, P4 provided 3 valid shares (≥ threshold),
        but the session fails because P5's single malformed message propagated fatally.
        P5 can repeat this on every subsequent signing attempt.
``` [8](#0-7) [9](#0-8)

### Citations

**File:** src/frost/eddsa/sign.rs (L99-167)
```rust
async fn do_sign_coordinator_v1(
    mut chan: SharedChannel,
    participants: ParticipantList,
    threshold: ReconstructionLowerBound,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: &mut impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    // --- Round 1.
    // * Wait for other parties' commitments.

    let mut commitments_map: BTreeMap<frost_ed25519::Identifier, round1::SigningCommitments> =
        BTreeMap::new();

    // signing share is the private_share
    let signing_share = keygen_output.private_share;

    // Step 1.1 (and implicitely 1.2)
    let (nonces, commitments) = round1::commit(&signing_share, rng);
    let nonces = Zeroizing::new(nonces);
    commitments_map.insert(me.to_identifier()?, commitments);

    // Step 1.3
    let commit_waitpoint = chan.next_waitpoint();

    // Step 1.4
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }

    let signing_package = frost_ed25519::SigningPackage::new(commitments_map, message.as_slice());

    let mut signature_shares: BTreeMap<frost_ed25519::Identifier, round2::SignatureShare> =
        BTreeMap::new();

    // Step 1.5
    let r2_wait_point = chan.next_waitpoint();
    chan.send_many(r2_wait_point, &signing_package)?;

    // --- Round 2
    // * Wait for each other's signature share
    // Step 2.3 (2.1 and 2.2 are implicit)
    let vk_package = keygen_output.public_key;
    let key_package = construct_key_package(threshold, me, signing_share, &vk_package)?;
    let key_package = Zeroizing::new(key_package);
    let signature_share = round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    // Step 2.5 (2.4 is implicit)
    signature_shares.insert(me.to_identifier()?, signature_share);
    for (from, signature_share) in recv_from_others(&chan, r2_wait_point, &participants, me).await?
    {
        signature_shares.insert(from.to_identifier()?, signature_share);
    }

    // --- Signature aggregation.
    // * Converted collected signature shares into the signature.
    // * Signature is verified internally during `aggregate()` call.

    // Step 2.6 and 2.7
    // We supply empty map as `verifying_shares` because we have disabled "cheater-detection" feature flag.
    // Feature "cheater-detection" only points to a malicious participant, if there's such.
    // It doesn't bring any additional guarantees.
    let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package);
    let signature = aggregate(&signing_package, &signature_shares, &public_key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    Ok(Some(signature))
```

**File:** src/frost/eddsa/sign.rs (L206-220)
```rust
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
```

**File:** src/protocol/helpers.rs (L6-26)
```rust
pub async fn recv_from_others<T>(
    chan: &SharedChannel,
    waitpoint: u64,
    participants: &ParticipantList,
    me: Participant,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let mut messages = Vec::with_capacity(participants.others(me).count());

    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
```

**File:** src/protocol/internal.rs (L338-340)
```rust
        let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
            rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
        Ok((from, decoded?))
```
