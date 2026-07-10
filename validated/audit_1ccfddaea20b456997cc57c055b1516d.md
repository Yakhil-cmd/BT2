### Title
FROST `PresignOutput` Derives `Clone` Enabling Nonce Reuse and Private Key Share Extraction — (`src/frost/mod.rs`, `src/frost/eddsa/sign.rs`, `src/frost/redjubjub/sign.rs`)

---

### Summary

The `PresignOutput` struct in the FROST signing path derives `Clone`, making it trivially possible for a caller to reuse the same signing nonces across two distinct signing sessions. In FROST, nonce reuse with the same key share across two messages allows any observer of both resulting signature shares to algebraically extract the participant's private signing share. This is the direct analog of the "deadline commented out" class: a safety mechanism that should prevent reuse of a one-time cryptographic object is absent, and the library API actively enables the dangerous pattern.

---

### Finding Description

In `src/frost/mod.rs`, the generic `PresignOutput<C>` struct is declared with `#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]`: [1](#0-0) 

The struct holds `nonces: SigningNonces<C>` — the per-participant secret nonce material that MUST be used at most once per signing session per the FROST specification (RFC 9591). Because `Clone` is derived, any caller can duplicate the `PresignOutput` before passing it to `sign_v2`, causing the same nonces to be consumed in two separate signing sessions.

The `sign_v2` public API for EdDSA takes `presignature: PresignOutput` by value (moves it), which appears to enforce single-use at the type level: [2](#0-1) 

However, because `PresignOutput` is `Clone`, the caller can trivially do:

```rust
let presign = run_presign(...);
let sig1 = sign_v2(..., presign.clone(), msg1);  // nonces used once
let sig2 = sign_v2(..., presign,          msg2);  // same nonces reused
```

The test suite itself demonstrates this pattern with `.clone()` on presign outputs: [3](#0-2) 

The same `Clone` derive applies to the `PresignOutput` used in the RedJubjub path (imported via `use super::{KeygenOutput, PresignOutput, SignatureOption}`): [4](#0-3) 

Additionally, `Serialize` + `Deserialize` are derived on `PresignOutput`, meaning nonces can be written to disk and reloaded, enabling nonce reuse across process restarts with no library-level barrier. [1](#0-0) 

In `do_sign_participant_v2` (EdDSA), the nonces are passed by reference to `round2::sign`, not consumed destructively at the call site: [5](#0-4) 

In `do_sign_coordinator_v2` (EdDSA), the same pattern holds — nonces are borrowed, not consumed: [6](#0-5) 

---

### Impact Explanation

In FROST, each participant's signature share in round 2 is computed as:

```
z_i = nonce_i + (binding_factor_i * nonce_hiding_i) + lambda_i * secret_share_i * challenge
```

If the same `(nonce_i, nonce_hiding_i)` pair is used for two messages `m1` and `m2` (producing challenges `c1` and `c2`), an observer with both signature shares `z_i^(1)` and `z_i^(2)` can solve for `secret_share_i`:

```
z_i^(1) - z_i^(2) = lambda_i * secret_share_i * (c1 - c2)
secret_share_i = (z_i^(1) - z_i^(2)) / (lambda_i * (c1 - c2))
```

This directly extracts the participant's private signing share. The impact matches: **Critical — Extraction, reconstruction, or disclosure of private signing shares.** [1](#0-0) 

---

### Likelihood Explanation

The `Clone` derive is part of the public API surface. Application developers routinely clone structs for retry logic, testing, logging, or passing to multiple subsystems. The library provides no documentation warning against cloning `PresignOutput`, no `#[must_use]` annotation, and no runtime guard. The `Serialize`/`Deserialize` derives further encourage persistence of presignatures to disk. Any application that stores or retries a presignature will trigger this vulnerability. A malicious coordinator who observes two signing sessions from the same participant using the same presignature can immediately extract that participant's key share. [1](#0-0) 

---

### Recommendation

1. **Remove `Clone` from `PresignOutput`** (and from the nonce-containing inner type if applicable). The struct should be non-`Clone` to make nonce reuse a compile-time error.
2. **Remove `Serialize`/`Deserialize` from `PresignOutput`**, or at minimum document that serialized presignatures must never be reused and must be deleted after use.
3. Consider wrapping `nonces` in a newtype that implements `Zeroize` on drop and does not implement `Clone`, enforcing single-use at the type level.
4. Add a `#[must_use]` annotation and explicit documentation stating that each `PresignOutput` is single-use and that reuse leads to private key extraction.

---

### Proof of Concept

```rust
// Attacker-observable nonce reuse via Clone
let presign_outputs = run_presign(&key_packages, threshold, actual_signers, rng).unwrap();

// Participant P's presign output
let (p, presign_p) = &presign_outputs[0];

// Clone the presign output — enabled by #[derive(Clone)] on PresignOutput
let presign_clone = presign_p.clone();

// First signing session: message M1
let sig1_shares = run_sign_v2_collect_shares(
    &key_packages, *p, presign_p.clone(), msg1
);

// Second signing session: message M2 — SAME NONCES REUSED
let sig2_shares = run_sign_v2_collect_shares(
    &key_packages, *p, presign_clone, msg2
);

// From sig1_shares[p] and sig2_shares[p], extract secret_share_p:
// secret_share_p = (z1 - z2) / (lambda_p * (c1 - c2))
// This is algebraically straightforward given both signature shares and public parameters.
```

The root cause is at: [1](#0-0) 

with the dangerous pattern demonstrated in the test suite at: [3](#0-2)

### Citations

**File:** src/frost/mod.rs (L36-41)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PresignOutput<C: Ciphersuite + Send + 'static> {
    /// The public nonce commitment.
    pub nonces: SigningNonces<C>,
    pub commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>>,
}
```

**File:** src/frost/eddsa/sign.rs (L64-88)
```rust
pub fn sign_v2(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound> + Copy,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::new();
    let chan = comms.shared_channel();
    let fut = fut_wrapper_v2(
        chan,
        participants,
        threshold.into(),
        me,
        coordinator,
        keygen_output,
        presignature,
        message,
    );
    Ok(make_protocol(comms, fut))
}
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

**File:** src/frost/eddsa/sign.rs (L583-596)
```rust
                let presign_output = presig
                    .iter()
                    .find(|(p, _)| p == &me)
                    .map(|(_, output)| output)
                    .unwrap();

                sign_v2(
                    participants,
                    threshold,
                    me,
                    coordinator,
                    keygen_output,
                    presign_output.clone(),
                    msg.clone(),
```

**File:** src/frost/redjubjub/sign.rs (L1-23)
```rust
//! This module and the frost one are supposed to have the same helper function
use super::{KeygenOutput, PresignOutput, SignatureOption};
use crate::{
    errors::{InitializationError, ProtocolError},
    frost::assert_sign_inputs,
    participants::{Participant, ParticipantList},
    protocol::{
        helpers::recv_from_others,
        internal::{make_protocol, Comms, SharedChannel},
        Protocol,
    },
    ReconstructionLowerBound,
};

use reddsa::frost::redjubjub::{
    aggregate,
    keys::{KeyPackage, PublicKeyPackage},
    round2,
    round2::SignatureShare,
    Identifier, RandomizedParams, Randomizer, SigningPackage,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
```
