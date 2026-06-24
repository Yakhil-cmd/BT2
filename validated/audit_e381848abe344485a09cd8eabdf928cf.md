Audit Report

## Title
Delegation Certificate Timestamp Not Validated Enables Stale-Delegation Replay by a Byzantine Node — (File: `rs/certification/src/lib.rs`)

## Summary
`verify_delegation_certificate` in `rs/certification/src/lib.rs` deserializes the `time` field from the NNS delegation certificate's state tree but never compares it against any current-time bound. A single Byzantine subnet node that captured a valid delegation certificate and a corresponding state tree before a subnet key rotation can replay both to clients after the rotation. Because the delegation's timestamp is never checked, the stale delegation passes verification, the old subnet public key is extracted, and the replayed (pre-rotation) state tree signature verifies successfully against that old key — causing clients to accept stale certified data as current.

## Finding Description
In `rs/certification/src/lib.rs` at lines 373–379, the inner struct used to deserialize the delegation certificate's state tree explicitly marks `time` as unused:

```rust
#[derive(Debug, Deserialize)]
struct SubnetCertificateData {
    #[allow(unused)] // currently delegation timestamps are not checked
    time: Leb128EncodedU64,
    subnet: BTreeMap<SubnetId, SubnetView>,
    canister_ranges: Option<BTreeMap<SubnetId, TreeCanisterRanges>>,
}
```

After deserialization (lines 392–398), `subnet_state.time` is never referenced again. The function proceeds directly to canister-range and public-key extraction (lines 400–479) and returns the subnet's public key without any staleness gate.

**Replay attack path (no threshold-majority compromise required):**

1. Before a subnet key rotation, the NNS issues delegation certificate `D_old` containing subnet public key `PK_old`. The subnet signs state trees with `PK_old`.
2. A Byzantine node (single node, below fault threshold) captures `D_old` and a legitimately signed state tree `T_old` (BLS-signed under `PK_old`).
3. A key rotation occurs: the NNS issues `D_new` with `PK_new`; honest nodes refresh their delegation within the 5-minute `DELEGATION_UPDATE_INTERVAL`.
4. The Byzantine node continues serving `D_old` + `T_old` to clients.
5. A client calls `verify_delegation_certificate(&D_old, ...)`:
   - BLS signature on `D_old` verifies against the NNS root key → **passes** (the signature was legitimately issued).
   - `time` field is parsed but never compared to current time → **passes** (no staleness check).
   - Canister ranges are present and valid → **passes**.
   - `PK_old` is extracted and returned.
6. The client verifies `T_old`'s BLS signature against `PK_old` → **passes** (it was legitimately signed).
7. The client accepts `T_old`'s certified data as the current certified state.

This path is exercised through all three call sites identified in the claim:
- `verify_certificate_internal` → `verify_delegation_certificate` (lines 338–344), used by `verify_certified_data` and `verify_certificate`.
- `validate_subnet_delegation_certificate` (line 493), called by the NNS delegation manager at lines 408–413 of `nns_delegation_manager.rs`.
- `packages/ic-signature-verification/src/canister_sig.rs` `verify_delegation` (lines 113–176), which performs the same check-free BLS verification and public-key extraction without any time validation.

Existing guards that are **insufficient**:
- The BLS signature check on the delegation certificate only proves the NNS signed it at some point; it does not prove freshness.
- The NNS delegation manager's 5-minute refresh (lines 55–58 of `nns_delegation_manager.rs`) applies only to honest nodes; a Byzantine node ignores it.
- The canister-range check verifies the canister is in scope but says nothing about key currency.

## Impact Explanation
A single Byzantine subnet node can cause clients to accept stale certified data as current after a subnet key rotation. Applications relying on `verify_certified_data` or canister-signature verification (ICCSA) for security-sensitive decisions (e.g., balance checks, upgrade status, access-control certified data) would act on outdated state. This matches the Medium allowed impact: **forged or stale certified response accepted only under constrained conditions**.

## Likelihood Explanation
The attack requires two conditions: (1) a subnet key rotation has occurred, and (2) a single Byzantine node below the consensus fault threshold has retained a pre-rotation delegation certificate and a pre-rotation signed state tree. Key rotations are infrequent but do occur (e.g., after security incidents or planned key ceremonies). Any node that was a subnet member before the rotation automatically satisfies condition (2). The attack is repeatable for as long as the Byzantine node remains in the subnet and the timestamp check remains absent. The code comment `// currently delegation timestamps are not checked` confirms this is a known, unmitigated gap.

## Recommendation
In `verify_delegation_certificate`, add a `current_time: Option<Time>` parameter. When provided, compare `subnet_state.time.0` (nanoseconds) against `current_time` and return `CertificateValidationError` if the delegation's certified time is older than a configurable maximum staleness bound (e.g., matching `DELEGATION_UPDATE_INTERVAL` of 5 minutes). Propagate this parameter through `verify_certificate_internal`, `verify_certified_data_internal`, `validate_subnet_delegation_certificate`, and the `packages/ic-signature-verification` crate's `verify_delegation` function so that staleness enforcement is uniform across all verification paths.

## Proof of Concept
**Deterministic integration test plan:**

1. Use `ic_certification_test_utils::CertificateBuilder` to generate a root of trust `(root_pk, root_sk)` and a subnet key pair `(pk_old, sk_old)`.
2. Build and sign a delegation certificate `D_old` at time `T_old` containing `pk_old` for subnet `S`.
3. Build and sign a state tree `T_old` at time `T_old` under `sk_old` with known `certified_data = b"stale"`.
4. Simulate a key rotation: generate `(pk_new, sk_new)`; build `D_new` at time `T_new = T_old + 10 min`.
5. Call `verify_delegation_certificate(&D_old, &subnet_id, &root_pk, Some(&canister_id), false)` — assert it returns `Ok(pk_old)` (no staleness rejection).
6. Call `verify_certified_data` with `D_old` + `T_old` — assert it returns `Ok(time)` with `certified_data = b"stale"`, demonstrating that stale certified data is accepted as current without error.
7. Assert that a correct implementation with a staleness bound of 5 minutes would return an error at step 5 when `current_time = T_new`.