### Title
FROST EdDSA Signing Coordinator Aborts Entire Session on Any Invalid Signature Share, Enabling Permanent DoS by a Single Malicious Participant - (File: src/frost/eddsa/sign.rs)

### Summary
The FROST EdDSA signing coordinator (`do_sign_coordinator_v1` and `do_sign_coordinator_v2`) unconditionally collects signature shares from **all** participants and passes them all to `aggregate()`. A single malicious participant sending an invalid share causes the final signature to fail internal verification inside `aggregate()`, aborting the entire signing session — even when the participant count exceeds the threshold and enough honest participants exist to produce a valid signature. With cheater detection explicitly disabled, the coordinator cannot identify the offending participant.

### Finding Description
In `do_sign_coordinator_v1` (lines 99–168) and `do_sign_coordinator_v2` (lines 179–223) of `src/frost/eddsa/sign.rs`, the coordinator executes the following sequence:

**Step 1 — Collect from all participants unconditionally:**
```rust
for (from, signature_share) in recv_from_others(&chan, r2_wait_point, &participants, me).await? {
    signature_shares.insert(from.to_identifier()?, signature_share);
}
```
`recv_from_others` (in `src/protocol/helpers.rs` lines 6–26) loops `while !seen.full()`, meaning it waits until **every** participant in the list has contributed. There is no early-exit once threshold-many shares are collected.

**Step 2 — Aggregate all shares with cheater detection disabled:**
```rust
let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package);
let signature = aggregate(&signing_package, &signature_shares, &public_key_package)
    .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
```
The `verifying_shares` argument is an empty `BTreeMap`. The code comment explicitly states this disables cheater detection. `aggregate()` in `frost_ed25519` sums all shares into a scalar `s`, constructs the signature `(R, s)`, and verifies it against the group public key. If any single share is invalid, `s` is incorrect, the signature fails verification, and `aggregate()` returns an error — propagated as `ProtocolError::AssertionFailed`, aborting the session.

The same pattern is present in `do_sign_coordinator_v2` at lines 206–220.

The FROST signing API explicitly supports `actual_signers > threshold`. The stress test at lines 463–489 iterates `actual_signers` from `min_signers` up to `max_signers`, confirming this is a documented and tested use case. When `N > T`, the protocol has redundancy that should allow it to tolerate up to `N − T` invalid contributors — but the implementation does not exploit this.

### Impact Explanation
A malicious participant included in any signing session sends a uniformly random scalar as their `round2::SignatureShare`. The coordinator sums all `N` shares (including the invalid one), producing an incorrect aggregate `s`. The final signature `(R, s)` fails the internal `aggregate()` verification check, returning `ProtocolError::AssertionFailed`. The entire signing session is aborted.

Because `verifying_shares` is empty, `aggregate()` cannot attribute the failure to any specific participant. The coordinator has no information