Audit Report

## Title
Byzantine Flex-Committee Block Proposer Can Forge `content_size` in `ResponsesTooLarge` to Permanently Terminate a Legitimate HTTP Outcall — (`rs/https_outcalls/consensus/src/payload_builder.rs`)

## Summary

In the `ResponsesTooLarge` validation branch of `validate_canister_http_payload_impl`, `ok_entry_sizes` is computed directly from `share.content.content_size()` — a self-reported metadata field — without any verification against an actual response body. A Byzantine node that is simultaneously a flex-committee member and the block proposer can sign a share with an arbitrarily inflated `content_size`, embed it in a crafted `ResponsesTooLarge` block payload, and cause all honest validators to accept a false termination of a legitimate HTTP outcall callback, permanently consuming cycles with no valid response delivered.

## Finding Description

**Root cause — `content_size` is trusted without verification in the `ResponsesTooLarge` path.**

In `payload_builder.rs`, the `ResponsesTooLarge` branch iterates over `all_seen_shares` and calls `validate_response_share` for each: [1](#0-0) 

`validate_response_share` checks callback ID, committee membership, duplicate signers, and registry version — but explicitly does **not** check `content_size` against any actual response body: [2](#0-1) 

After share validation, `ok_entry_sizes` is built by mapping each non-reject share through `count_bytes_from_parts`, passing `share.content.content_size()` directly as the size parameter: [3](#0-2) 

`smallest_sum` is then compared against `MAX_CANISTER_HTTP_PAYLOAD_SIZE` to decide whether the `ResponsesTooLarge` claim is valid: [4](#0-3) 

**Contrast with the `TooManyRejects`/`flexible_responses` path**, which calls `validate_flexible_response_with_proof` and verifies both `content_hash` and `content_size` against the actual response body: [5](#0-4) 

The `ResponsesTooLarge` variant carries only `CanisterHttpResponseShare` objects (metadata + signature), not full response bodies, so this stronger check is structurally absent from that path: [6](#0-5) 

**The pool manager guard does not protect the consensus path.** The pool manager enforces `content_size == response.content.count_bytes()` when admitting artifacts: [7](#0-6) 

However, a Byzantine block proposer constructs the block payload directly and is not constrained to use only pool-admitted shares. They can embed any validly-signed `CanisterHttpResponseShare` — signed with their own legitimate key — directly into the `ResponsesTooLarge` error in the block they propose.

**Exploit flow:**

Setup: `flex_committee = {A (Byzantine), B, C}`, `min_responses = 3`.

1. Byzantine node A signs a `CanisterHttpResponseShare` with `content_size = MAX_CANISTER_HTTP_PAYLOAD_SIZE + 1`. The signature is cryptographically valid (A signs with its own key).
2. A waits until it is the block proposer (deterministic rotation in IC consensus).
3. A crafts `FlexibleCanisterHttpError::ResponsesTooLarge` with `all_seen_shares = [A's inflated share]`, omitting honest nodes B and C.
4. Validators compute:
   - `num_unseen = 3 - 1 = 2`
   - `min_known_ok_needed = 3 - 2 = 1`
   - `ok_entry_sizes = [MAX + 1 + overhead]`
   - `smallest_sum > MAX_CANISTER_HTTP_PAYLOAD_SIZE` → **accepted as valid**
5. The callback is permanently terminated with a `ResponsesTooLarge` error.

## Impact Explanation

A legitimate HTTP outcall is permanently terminated via consensus with a forged `ResponsesTooLarge` error. The callback can never be retried once finalized. Cycles are consumed without a valid response delivered to the canister. The canister has no recourse — the error is indistinguishable from a genuine `ResponsesTooLarge` condition. This constitutes a targeted, application-level DoS against specific HTTP outcalls, matching the **High ($2,000–$10,000)** impact class: *Application/platform-level DoS or subnet availability impact not based on raw volumetric DDoS*, with concrete, irreversible user and protocol harm (permanent cycle loss, no response).

## Likelihood Explanation

The attack requires a single Byzantine node to hold two roles simultaneously: flex-committee membership and block proposer. Both are legitimate, rotating protocol roles. Block proposer assignment rotates deterministically in IC consensus, so a Byzantine committee member will eventually hold the proposer role while the target outcall remains pending. No threshold corruption, no key leakage, no external dependency, and no victim mistake is required — only a single Byzantine node with a valid signing key. The outcall remains pending until resolved, giving the attacker an unbounded window. The attack is repeatable across any pending outcall for which the Byzantine node is a committee member.

## Recommendation

In the `ResponsesTooLarge` validation branch, after `validate_response_share` passes, reject any non-reject share whose `content_size` exceeds the per-response hard cap (`MAX_CANISTER_HTTP_RESPONSE_BYTES`). A single share cannot legitimately report a `content_size` larger than this bound. Add a check analogous to:

```rust
// After validate_response_share, inside the ResponsesTooLarge branch:
if !share.content.is_reject()
    && share.content.content_size() > MAX_CANISTER_HTTP_RESPONSE_BYTES as u32
{
    return invalid_artifact(
        InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit { ... }
    );
}
```

This mirrors the size enforcement already present in the pool manager and closes the gap between the pool-admission path and the consensus-validation path. [8](#0-7) 

## Proof of Concept

The existing test `flexible_error_responses_too_large_valid` already demonstrates that the validator accepts a `ResponsesTooLarge` payload built entirely from `metadata_share_with_content_size` — shares with arbitrary `content_size` values and no actual response body: [9](#0-8) 

A minimal PoC variant: set `huge_content_size = MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 + 1`, use `num_nodes = 3`, `min_responses = 3`, and include only a single share (`all_seen_shares` length = 1). This yields `min_known_ok_needed = 1` and `smallest_sum = MAX + 1 + overhead > MAX`. The test will pass `assert_matches!(result, Ok(()))`, confirming the invariant is broken with a single Byzantine share.

### Citations

**File:** rs/https_outcalls/consensus/src/payload_builder.rs (L771-781)
```rust
                    for share in all_seen_shares {
                        validate_response_share(
                            share,
                            callback_id,
                            flex_committee,
                            &mut seen_signers,
                            consensus_registry_version,
                            context.refund_status.per_replica_allowance,
                        )
                        .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;
                    }
```

**File:** rs/https_outcalls/consensus/src/payload_builder.rs (L789-799)
```rust
                    let mut ok_entry_sizes: Vec<usize> = all_seen_shares
                        .iter()
                        .filter(|share| !share.content.is_reject())
                        .map(|share| {
                            FlexibleCanisterHttpResponseWithProof::count_bytes_from_parts(
                                &context.request.sender,
                                share.content.content_size() as usize,
                                share,
                            )
                        })
                        .collect();
```

**File:** rs/https_outcalls/consensus/src/payload_builder.rs (L811-818)
```rust
                    let smallest_sum: usize = ok_entry_sizes.iter().take(min_known_ok_needed).sum();
                    if smallest_sum <= MAX_CANISTER_HTTP_PAYLOAD_SIZE {
                        return invalid_artifact(
                            InvalidCanisterHttpPayloadReason::FlexibleResponsesNotTooLarge(
                                callback_id,
                            ),
                        );
                    }
```

**File:** rs/https_outcalls/consensus/src/payload_builder/utils.rs (L173-187)
```rust
    let calculated_hash = crypto_hash(&response_with_proof.response);
    if &calculated_hash != response_with_proof.proof.content.content_hash() {
        return Err(InvalidCanisterHttpPayloadReason::ContentHashMismatch {
            metadata_hash: response_with_proof.proof.content.content_hash().clone(),
            calculated_hash,
        });
    }

    let calculated_size = response_with_proof.response.content.count_bytes() as u32;
    if calculated_size != response_with_proof.proof.content.content_size() {
        return Err(InvalidCanisterHttpPayloadReason::ContentSizeMismatch {
            metadata_size: response_with_proof.proof.content.content_size(),
            calculated_size,
        });
    }
```

**File:** rs/https_outcalls/consensus/src/payload_builder/utils.rs (L208-251)
```rust
pub(crate) fn validate_response_share(
    share: &CanisterHttpResponseShare,
    callback_id: CallbackId,
    flex_committee: &BTreeSet<NodeId>,
    seen_signers: &mut HashSet<NodeId>,
    consensus_registry_version: RegistryVersion,
    per_replica_allowance: Cycles,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
    check_refund_allowance(&share.content.payment_receipt, per_replica_allowance)?;

    if share.content.id() != callback_id {
        return Err(
            InvalidCanisterHttpPayloadReason::FlexibleCallbackIdMismatch {
                callback_id,
                mismatched_id: share.content.id(),
            },
        );
    }

    let signer = share.signature.signer;
    if !seen_signers.insert(signer) {
        return Err(InvalidCanisterHttpPayloadReason::FlexibleDuplicateSigner {
            callback_id,
            signer,
        });
    }
    if !flex_committee.contains(&signer) {
        return Err(
            InvalidCanisterHttpPayloadReason::FlexibleSignerNotInCommittee {
                callback_id,
                signer,
            },
        );
    }

    if share.content.registry_version() != consensus_registry_version {
        return Err(InvalidCanisterHttpPayloadReason::RegistryVersionMismatch {
            expected: consensus_registry_version,
            received: share.content.registry_version(),
        });
    }

    Ok(())
}
```

**File:** rs/types/types/src/batch/canister_http.rs (L48-53)
```rust
    ResponsesTooLarge {
        callback_id: CallbackId,
        all_seen_shares: Vec<CanisterHttpResponseShare>,
        total_requests: u32,
        min_responses: u32,
    },
```

**File:** rs/https_outcalls/consensus/src/pool_manager.rs (L544-549)
```rust
                        if share.content.content_size() != response.content.count_bytes() as u32 {
                            return Some(CanisterHttpChangeAction::HandleInvalid(
                                share.clone(),
                                "Content size does not match the response".to_string(),
                            ));
                        }
```

**File:** rs/https_outcalls/consensus/src/pool_manager.rs (L558-573)
```rust
                        // An honest replica enforces that response.content.count_bytes() does not exceed max_response_bytes
                        // when the content is `Success`. However it doesn't enroce anything in the case of `Failure`.
                        // As we still want to set a limit for failure, we enforce 1KB, which is reasonable for
                        // an error message.

                        // for flexible calls, max_response_bytes is always None
                        if let Err(e) = validate_response_size(response, context.max_response_bytes)
                        {
                            return Some(CanisterHttpChangeAction::HandleInvalid(
                                share.clone(),
                                format!(
                                    "Http Response for request ID {} is too large: {}",
                                    response.id, e
                                ),
                            ));
                        }
```

**File:** rs/https_outcalls/consensus/src/payload_builder/tests.rs (L3779-3808)
```rust
fn flexible_error_responses_too_large_valid() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=2, all 4 committee members responded with huge OK →
    // num_unseen=0, min_known_ok_needed=2, smallest 2 × ~1.1 MiB > 2 MiB.
    let huge_content_size = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let all_seen_shares: Vec<_> = (0..4)
            .map(|i| metadata_share_with_content_size(callback_id.get(), i, huge_content_size))
            .collect();

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares,
                total_requests: 4,
                min_responses: 2,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(result, Ok(()));
    });
```
