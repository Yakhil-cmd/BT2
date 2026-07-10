### Title
Overly-Restrictive Coordinator Membership Check in FROST `assert_sign_inputs` Causes Permanent Denial of Signing - (File: src/frost/mod.rs)

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` incorrectly requires the `coordinator` to be a member of the signing `participants` list. In the FROST protocol, the coordinator is an aggregation entity that does not need to hold a key share and does not need to be a signing participant. This check causes all FROST signing attempts that use an external (non-participant) coordinator to always fail with `MissingParticipant`, permanently denying signing for honest parties under a valid and documented FROST configuration.

### Finding Description

`assert_sign_inputs` performs the following validation:

```rust
// ensure the coordinator is a participant
if !participants.contains(coordinator) {
    return Err(InitializationError::MissingParticipant {
        role: "coordinator",
        participant: coordinator,
    });
}
``` [1](#0-0) 

The `participants` list passed to this function is the set of **signing participants** — parties that hold key shares and contribute signature shares. The `coordinator` is a separate role: it collects commitments, distributes the signing package, and aggregates signature shares. Per the FROST specification (RFC 9591), the coordinator is explicitly described as an entity with no special trust that may or may not be a signing participant. It is a freely user-specified parameter.

By requiring `coordinator` to be present in the signing `participants` list, the function rejects any configuration where an external party (e.g., a dedicated aggregation server, a TEE enclave, or any non-keyholder) acts as coordinator. This is a valid and common FROST deployment pattern.

The `assert_sign_inputs` function is the entry-point guard for the EdDSA/FROST signing flow: [2](#0-1) 

Any caller that passes a coordinator not present in the signing participant set will receive an `InitializationError::MissingParticipant` error and the signing protocol will never start.

### Impact Explanation

**High — Permanent denial of signing for honest parties under valid protocol inputs.**

Any deployment that uses an external coordinator (a party that is not one of the threshold signers) will be permanently unable to initiate the FROST signing protocol. The error is deterministic and unconditional: every such call fails at initialization before any cryptographic work is done. This matches the allowed impact: *"Permanent denial of signing … for honest parties under valid protocol inputs and documented trust assumptions."*

### Likelihood Explanation

The FROST protocol explicitly supports external coordinators. Any integrator following the FROST RFC or standard documentation who designates a non-participant as coordinator will hit this failure on every signing attempt. The likelihood is high because external coordinators are a standard and documented deployment pattern for FROST.

### Recommendation

Remove the check that requires the coordinator to be in the signing participant list. The coordinator's identity only needs to be known to participants for routing purposes; it does not need to hold a key share or appear in the participant set:

```diff
-    // ensure the coordinator is a participant
-    if !participants.contains(coordinator) {
-        return Err(InitializationError::MissingParticipant {
-            role: "coordinator",
-            participant: coordinator,
-        });
-    }
```

If the coordinator must be authenticated for message-routing purposes, that concern should be handled at the network/transport layer, not by requiring coordinator membership in the signing set.

### Proof of Concept

1. Generate a keygen output for participants `[P1, P2, P3]` with threshold 2.
2. Designate an external party `P_ext` (not in `[P1, P2, P3]`) as coordinator.
3. Call `assert_sign_inputs(&[P1, P2], threshold, P1, P_ext)`.
4. Observe: returns `Err(InitializationError::MissingParticipant { role: "coordinator", participant: P_ext })` unconditionally.
5. No signing can proceed despite `P1` and `P2` being valid threshold signers with correct key shares.

The root cause is at: [1](#0-0)

### Citations

**File:** src/frost/mod.rs (L120-125)
```rust
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
```

**File:** src/frost/mod.rs (L152-158)
```rust
    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
```
