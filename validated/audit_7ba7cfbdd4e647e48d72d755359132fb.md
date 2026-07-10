### Title
Single Malicious Participant Causes Unattributable Signing Failure in FROST EdDSA Coordinator — (`src/frost/eddsa/sign.rs`)

---

### Summary

The FROST EdDSA signing coordinator (`do_sign_coordinator_v1` / `do_sign_coordinator_v2`) collects signature shares from **every** participant in the session via `recv_from_others`, then calls `aggregate()` with an **empty** verifying-shares map (cheater-detection explicitly disabled). A single malicious participant can submit a syntactically valid but cryptographically invalid signature share; `aggregate()` will fail because the combined signature does not verify, and the coordinator has no mechanism to attribute the failure to any specific participant. The signing session is aborted with no actionable information, and the attack can be repeated indefinitely.

---

### Finding Description

**Root cause — `do_sign_coordinator_v1`** (lines 150–165):

```rust
for (from, signature_share) in recv_from_others(&chan, r2_wait_point, &participants, me).await? {
    signature_shares.insert(from.to_identifier()?, signature_share);
}
// ...
let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package); // ← empty verifying shares
let signature = aggregate(&signing_package, &signature_shares, &public_key_package)
    .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
``` [1](#0-0) 

The same pattern appears in `do_sign_coordinator_v2`:

```rust
for (from, signature_share) in
    recv_from_others(&chan, sign_waitpoint, &participants, me).await?
{
    signature_shares.insert(from.to_identifier()?, signature_share);
}
// ...
let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package);
let signature = aggregate(&signing_package, &signature_shares, &public_key_package)
    .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
``` [2](#0-1) 

The code comment explicitly acknowledges the design choice:

> "We supply empty map as `verifying_shares` because we have disabled 'cheater-detection' feature flag. Feature 'cheater-detection' only points to a malicious participant, if there's such. It doesn't bring any additional guarantees." [3](#0-2) 

The `recv_from_others` helper requires **all** participants to respond before proceeding:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;
    if seen.put(from) {
        messages.push((from, msg));
    }
}
``` [4](#0-3) 

**Attack path:**

1. A malicious participant is included in the signing session's `participants` list.
2. In Round 2, instead of computing `round2::sign(...)` honestly, the malicious participant sends an arbitrary (invalid) `SignatureShare` to the coordinator.
3. The coordinator accumulates all shares into `signature_shares` without per-share verification.
4. `aggregate()` computes the combined scalar `s = Σ sᵢ` and verifies `s·G == R + c·Y`. Because one `sᵢ` is wrong, the equation fails.
5. `aggregate()` returns an error; the coordinator propagates `ProtocolError::AssertionFailed(...)`.
6. The coordinator has no way to determine which participant submitted the bad share (the verifying-shares map is empty, so per-share verification is skipped).
7. The malicious participant can repeat this in every subsequent signing session they are included in.

The same structural issue exists in `do_sign_coordinator_v1` (lines 126–128 for Round 1 commitment collection, and lines 150–165 for Round 2 share collection). [5](#0-4) 

---

### Impact Explanation

**High — Permanent denial of signing for honest parties.**

Because cheater-detection is disabled, the coordinator cannot identify which participant submitted the invalid share. Without that attribution:

- The coordinator cannot exclude the malicious participant from future sessions.
- Every signing attempt that includes the malicious participant will fail at `aggregate()`.
- If the malicious participant is always reachable and always included (e.g., because the signing policy requires their participation, or because the coordinator has no out-of-band mechanism to blacklist them), signing is permanently blocked.
- Even if the coordinator tries random subsets, without attribution the search space is exponential in the number of participants.

This matches the allowed impact: **"High: Permanent denial of signing … for honest parties under valid protocol inputs and documented trust assumptions."**

---

### Likelihood Explanation

**High.** Any participant in the signing session can execute this attack by sending a single random scalar as their `SignatureShare`. No special cryptographic capability is required — the attacker does not need to know any secret material. The attack is one message per signing round and is completely undetectable by the coordinator with the current code.

---

### Recommendation

Enable per-share verification by supplying a populated `verifying_shares` map to `aggregate()`. FROST's cheater-detection feature computes `sᵢ·G` and checks it against the participant's public commitment, identifying the exact culprit before the final aggregation step. The coordinator can then exclude the identified participant and retry with the remaining honest set.

Concretely, replace:

```rust
let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package);
```

with a map populated from each participant's `VerifyingShare` (derivable from their `SigningShare` and the public polynomial commitments already exchanged during DKG). This is the standard FROST cheater-detection path and adds only one scalar multiplication per participant.

---

### Proof of Concept

```
Participants: {P1 (coordinator), P2 (honest), P3 (malicious)}
Threshold: 2, Signing set: {P1, P2, P3}

Round 1 (v1 only):
  P2 → P1: valid commitment
  P3 → P1: valid commitment   (P3 behaves honestly here)

Round 2:
  P1 broadcasts signing_package to all
  P2 → P1: valid signature_share  (s2 = H·k2 + r·σ2)
  P3 → P1: random scalar s3'      (attacker-chosen garbage)

Coordinator:
  signature_shares = {P1: s1, P2: s2, P3: s3'}
  s_total = s1 + s2 + s3'   ← wrong
  aggregate() verifies s_total·G == R + c·Y  → FAILS
  Returns ProtocolError::AssertionFailed("...")
  Coordinator cannot tell whether P2 or P3 is the culprit.

P3 repeats this in every subsequent session → signing never succeeds.
``` [6](#0-5) [7](#0-6)

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

**File:** src/protocol/helpers.rs (L19-24)
```rust
    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }
```
