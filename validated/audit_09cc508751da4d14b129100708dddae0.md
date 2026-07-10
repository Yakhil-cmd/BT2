### Title
Forked `reddsa` with Disabled Cheater Detection Allows Any Malicious Signing Participant to Permanently Deny RedJubJub Threshold Signing — (`Cargo.toml`, `src/frost/redjubjub/sign.rs`)

---

### Summary

The codebase depends on a non-standard, unaudited fork of `reddsa` pinned to a specific git commit, and explicitly constructs `PublicKeyPackage` with an empty verifying-share map, disabling per-share cheater detection during FROST aggregation. A single malicious participant can send a crafted invalid `SignatureShare`, causing `aggregate()` to fail at the group-level verification step. Because no individual share verification is performed, the coordinator cannot identify the offending participant, making the denial of signing persistent across retries that include the same participant set.

---

### Finding Description

**Root cause 1 — Forked, unaudited `reddsa` dependency:**

`Cargo.toml` lines 46–49 pull `reddsa` from a NEAR-controlled GitHub fork pinned to a single commit, not from the official, published, audited crate on crates.io:

```toml
# This project has been forked due to incompatibility problems with cheater detection feature activated on the original Zcash repo
reddsa = { git = "https://github.com/near/reddsa", rev = "c7cd92a55f7399d8d7f8c0ac386445b5f898f197", ... }
``` [1](#0-0) 

The stated reason for the fork is to remove the cheater-detection feature present in the upstream Zcash repository. Additionally, `deny.toml` explicitly suppresses a known security advisory (`RUSTSEC-2023-0089`) for a deprecated crate (`atomic-polyfill`) that is transitively pulled in by this fork: [2](#0-1) 

**Root cause 2 — Empty `PublicKeyPackage` disables per-share verification:**

In `src/frost/redjubjub/sign.rs`, the coordinator constructs `PublicKeyPackage` with an empty `BTreeMap`, providing no individual verifying shares:

```rust
// We use empty BTreeMap because "cheater-detection" feature is disabled
// Feature "cheater-detection" unveils existant malicious participants
let pk_package = PublicKeyPackage::new(BTreeMap::new(), keygen_output.public_key);
``` [3](#0-2) 

The FROST `aggregate()` function normally verifies each received `SignatureShare` against the corresponding participant's verifying share before combining them. With an empty map, this per-share check is skipped entirely. The only remaining check is a group-level verification of the combined signature against the master public key. [4](#0-3) 

**Attack path:**

A malicious participant in `do_sign_participant` sends a syntactically valid but cryptographically incorrect `SignatureShare` to the coordinator at `sign_waitpoint`. The coordinator collects all shares into `signature_shares` and calls `aggregate()`. Because no per-share verification is performed, the bad share is included in the combination. The combined value fails the group-level signature check inside `aggregate()`, which returns an error. The coordinator maps this to `ProtocolError::ErrorFrostAggregation` and the signing round fails. The coordinator has no information about which participant submitted the bad share. [5](#0-4) 

---

### Impact Explanation

**High — Permanent denial of signing for honest parties.**

A single malicious participant can abort every signing round that includes them by submitting an invalid `SignatureShare`. Because cheater detection is disabled, the coordinator receives only a generic `ErrorFrostAggregation` with no attribution. Honest parties cannot determine which participant to exclude. If the malicious participant is always present in the signing quorum (e.g., they hold a required share in a tight threshold), signing is permanently blocked. Even in looser configurations, the honest parties must exhaustively try all participant subsets to isolate the cheater, which is exponential in the number of participants.

---

### Likelihood Explanation

Any participant who has completed the presign phase and holds a valid `PresignOutput` can trivially corrupt their `SignatureShare` before sending it. No special cryptographic capability is required — flipping a single bit in the share suffices. The attack is repeatable across every signing invocation that includes the malicious participant.

---

### Recommendation

1. **Restore per-share verification**: Populate `PublicKeyPackage` with the actual verifying shares derived from `keygen_output` so that `aggregate()` can identify and reject individual bad shares before attempting combination.
2. **Use the upstream published `reddsa` crate**: Replace the git-pinned fork with the official crates.io release, which includes the cheater-detection feature and has received broader review.
3. **Remove the `RUSTSEC-2023-0089` advisory suppression** in `deny.toml` once the dependency on the deprecated `atomic-polyfill` crate is eliminated.
4. **Document the trust assumption explicitly**: If the fork and disabled cheater detection are intentional design choices, the public API documentation must clearly state that all signing participants are assumed honest, and callers are responsible for participant vetting.

---

### Proof of Concept

1. A set of `N` participants complete DKG and presigning for RedJubJub.
2. One malicious participant, instead of computing `round2::sign(...)` correctly, constructs a `SignatureShare` with a random scalar value.
3. The malicious participant sends this invalid share to the coordinator via `chan.send_private(sign_waitpoint, coordinator, &signature_share)`.
4. The coordinator collects all shares at lines 162–168 of `sign.rs` and calls `aggregate(...)` at line 178.
5. Because `PublicKeyPackage` was constructed with `BTreeMap::new()` (line 176), no per-share check is performed.
6. The combined value fails the group-level check inside `aggregate()`, which returns `Err(...)`.
7. The coordinator maps this to `ProtocolError::ErrorFrostAggregation` (line 184) and returns it to the caller.
8. The signing round fails. The coordinator has no information identifying the malicious participant.
9. Repeating steps 2–8 on every signing invocation permanently prevents honest parties from producing a valid RedJubJub threshold signature.

### Citations

**File:** Cargo.toml (L46-49)
```text
# This project has been forked due to incompatibility problems with cheater detection feature activated on the original Zcash repo
reddsa = { git = "https://github.com/near/reddsa", rev = "c7cd92a55f7399d8d7f8c0ac386445b5f898f197", default-features = false, features = [
  "frost",
] }
```

**File:** deny.toml (L5-7)
```text
ignore = [
    "RUSTSEC-2023-0089" # deprecated atomic-polyfill necessary by the serialization feature of rerandomized-frost 2.2.0 called in reddsa
]
```

**File:** src/frost/redjubjub/sign.rs (L162-184)
```rust
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
```
