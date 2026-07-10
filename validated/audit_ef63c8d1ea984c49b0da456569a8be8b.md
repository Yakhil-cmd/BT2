### Title
Coordinator-Supplied `Randomizer` in RedJubjub FROST Signing Is Not Verified by Participants — (`src/frost/redjubjub/sign.rs`)

---

### Summary

In the RedJubjub FROST signing protocol, each non-coordinator participant receives the `Randomizer` value directly from the coordinator over the channel and uses it without any verification against a locally-known expected value. Because the `Randomizer` determines the effective signing key (`X + r·G`), a malicious coordinator can substitute any randomizer, causing honest participants to produce signature shares for an attacker-chosen effective public key.

---

### Finding Description

In `do_sign_participant` (`src/frost/redjubjub/sign.rs`, lines 197–235), the participant's Round 1 action is to receive the `Randomizer` from the coordinator:

```rust
// Receive the Randomizer from the coordinator
let wait_round_1 = chan.next_waitpoint();
let randomizer = loop {
    let (from, randomizer): (_, Randomizer) = chan.recv(wait_round_1).await?;
    if from != coordinator {
        continue;
    }
    break randomizer;
};
``` [1](#0-0) 

This randomizer is then used directly in the signature share computation:

```rust
let signing_package = SigningPackage::new(presignature.commitments_map, &message);
let signature_share = round2::sign(&signing_package, &nonces, &key_package, randomizer)
    .map_err(|_| ProtocolError::ErrorFrostSigningFailed)?;
``` [2](#0-1) 

Critically, the function signature of `do_sign_participant` does **not** include a `randomizer` parameter:

```rust
async fn do_sign_participant(
    mut chan: SharedChannel,
    threshold: ReconstructionLowerBound,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
) -> Result<SignatureOption, ProtocolError>
``` [3](#0-2) 

This means the participant has no locally-held expected randomizer to compare against. The coordinator-supplied value is accepted unconditionally.

Contrast this with the `message` field: participants hold a local copy of `message` (passed as a parameter) and use it directly to construct the `SigningPackage`, so the coordinator cannot substitute the message. No equivalent protection exists for the `randomizer`.

The public `sign` entry point accepts `randomizer: Option<Randomizer>` from each caller:

```rust
pub fn sign(
    participants: &[Participant],
    ...
    message: Vec<u8>,
    randomizer: Option<Randomizer>,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError>
``` [4](#0-3) 

But this caller-supplied randomizer is never forwarded to `do_sign_participant` — it is only used by the coordinator path. Non-coordinator participants therefore have no mechanism to enforce their expected randomizer.

---

### Impact Explanation

In RedJubjub, the `Randomizer` `r` shifts the effective verification key to `X + r·G`. A malicious coordinator who sends randomizer `r'` (instead of the agreed-upon `r`) to all participants causes them to produce valid signature shares for the effective key `X + r'·G`. The coordinator can then aggregate these shares into a fully valid threshold signature for an attacker-chosen effective public key — without any honest participant detecting the substitution.

This constitutes **unauthorized creation of a valid threshold signature for attacker-chosen inputs** (the effective key), matching the Critical impact tier.

---

### Likelihood Explanation

The coordinator is a single participant in the protocol. A single malicious coordinator is sufficient to execute this attack — no collusion among multiple participants is required. The coordinator controls the randomizer broadcast and participants have no defense. This is directly analogous to the external report where a single malicious observer could replace the `sender` field.

---

### Recommendation

Each non-coordinator participant should receive the `randomizer` as a local parameter (passed through `do_sign_participant`'s function signature) and verify that the coordinator-sent randomizer matches their locally-expected value before computing the signature share. Specifically:

1. Thread the `randomizer: Option<Randomizer>` parameter from `sign` through `fut_wrapper` into `do_sign_participant`.
2. In `do_sign_participant`, after receiving the coordinator's randomizer, assert it equals the locally-expected value (if one was provided).
3. If no local randomizer is specified, participants should at minimum verify that all participants received the same randomizer (e.g., via a commitment round before the randomizer is revealed).

---

### Proof of Concept

1. Honest participants call `sign(..., message, randomizer: Some(r_expected))`.
2. The malicious coordinator calls `sign(..., message, randomizer: Some(r_attacker))`.
3. The coordinator's `do_sign_coordinator` sends `r_attacker` to all participants via `chan.send_*`.
4. Each participant's `do_sign_participant` receives `r_attacker` from the coordinator and uses it unconditionally (lines 216–223), ignoring `r_expected` (which was never passed to them).
5. All participants produce signature shares for effective key `X + r_attacker·G`.
6. The coordinator aggregates a valid threshold signature for `X + r_attacker·G` — an attacker-chosen effective public key — without any honest participant's awareness. [5](#0-4)

### Citations

**File:** src/frost/redjubjub/sign.rs (L39-48)
```rust
pub fn sign(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
    randomizer: Option<Randomizer>,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
```

**File:** src/frost/redjubjub/sign.rs (L197-205)
```rust
async fn do_sign_participant(
    mut chan: SharedChannel,
    threshold: ReconstructionLowerBound,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
) -> Result<SignatureOption, ProtocolError> {
```

**File:** src/frost/redjubjub/sign.rs (L215-230)
```rust
    // Receive the Randomizer from the coordinator
    let wait_round_1 = chan.next_waitpoint();
    let randomizer = loop {
        let (from, randomizer): (_, Randomizer) = chan.recv(wait_round_1).await?;
        if from != coordinator {
            continue;
        }
        break randomizer;
    };

    let key_package = construct_key_package(threshold, me, &keygen_output)?;
    let key_package = Zeroizing::new(key_package);
    let nonces = Zeroizing::new(presignature.nonces);
    let signing_package = SigningPackage::new(presignature.commitments_map, &message);
    let signature_share = round2::sign(&signing_package, &nonces, &key_package, randomizer)
        .map_err(|_| ProtocolError::ErrorFrostSigningFailed)?;
```
