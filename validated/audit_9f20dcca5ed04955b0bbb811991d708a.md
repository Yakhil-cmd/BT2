### Title
No refund/cancel mechanism when `bridge::send_token` burns Sui-originated tokens before destination-chain approval - (File: `crates/sui-framework/packages/bridge/sources/bridge.move`)

### Summary
The Sui native bridge's Move module burns the user's coin immediately and irrevocably when a Sui→destination-chain transfer is initiated, before the message has any committee signatures or destination-chain finality. There is no on-chain function to reclaim, mint back, or otherwise refund the burned tokens if the transfer never gets approved/relayed to completion on the other side. This mirrors the Chakra `H-11` root cause: value is destroyed/locked optimistically on the source side of a cross-chain flow, and there is no fallback path if the destination side never finalizes the transfer.

### Finding Description
`send_token`/`send_token_v2` call `send_token_internal`, which unconditionally burns the user's `Coin<T>` via `inner.treasury.burn(token)` and stores a `BridgeRecord{ message, verified_signatures: option::none(), claimed: false }` keyed by `message.key()` [1](#0-0) .

At this point the caller's funds are gone from Sui state. The only path back to "completion" is off-chain: the bridge client/committee must later call `approve_token_transfer` (attaching signatures to the existing record) [2](#0-1)  and then relay the approved message to the destination chain (e.g., EVM `SuiBridge.sol`) to actually unlock funds there.

Scanning the entire `bridge::bridge` module's public API surface — `create`, `init_bridge_committee`, `committee_registration`, `update_node_url`, `register_foreign_token`, `send_token`, `send_token_v2`, `approve_token_transfer`, `claim_token`, `claim_and_transfer_token`, `execute_system_message`, plus read helpers [3](#0-2)  — there is no `cancel_transfer`, `refund_token`, `reclaim`, or any function that mints/unlocks tokens back to the original sender when a `BridgeRecord` is never approved, when the destination chain later rejects the route/token (e.g., unsupported token type or emergency pause on the far side), or when the off-chain relayer/committee simply never submits `approve_token_transfer`. A codebase-wide search for "refund" found no occurrence in any bridge source or test file. `BridgeRecord.verified_signatures` can remain `option::none()` forever with the underlying coin already burned, and there is no timeout, expiry, or cancellation path defined in Move.

This is structurally identical to the reported Chakra issue: the source-chain leg (burn) is committed unconditionally and irreversibly at initiation time, while the destination-chain leg (approval + unlock/mint) is a separate, later, off-chain-coordinated step that can fail or never happen (destination bridge paused, committee never reaches quorum, target route/token becomes invalid, relayer failure, or governance intervention) — and the protocol has no compensating refund/burn-reversal mechanism for the source-chain user.

### Impact Explanation
An ordinary Sui token holder who calls `send_token`/`send_token_v2` has their coins burned unconditionally. If the corresponding message is never approved and relayed to completion (for any reason outside the caller's control — bridge pause, committee unavailability/rotation, destination route/token invalidation, relayer downtime, or governance blocklist changes on the committee before quorum is reached), the user has no recourse: the tokens are permanently destroyed with no way to reclaim them on Sui and no unlock ever occurring on the destination chain. This is a permanent, unrecoverable loss of user funds triggered purely by unprivileged, public input (`send_token`) combined with conditions/timing outside the caller's control — matching the "permanent fund lock" / harmful smart-contract behavior class, and could rise to Critical-level fund loss at scale since burns are not automatically reversible and no protocol-level safety valve exists.

### Likelihood Explanation
Likelihood is credible but not certain to trigger, since it depends on external/off-chain conditions (committee availability, relayer liveness, destination-chain state) rather than a directly exploitable on-chain bug by itself. However, unlike the EVM-side `BridgeLimiter`/mature-message bypass logic (which resolves stuck limiter-blocked transfers after 48h), there is no analogous timeout/expiry/cancellation logic for a transfer whose Sui-side record is simply never approved at all — meaning any interruption or failure in the off-chain relayer/committee pipeline permanently strands the burned funds with no on-chain remedy. Given the multi-actor, multi-chain nature of the relay pipeline (client → syncer → orchestrator → aggregator → committee signatures → destination execution), transient or permanent failures in any of these unprivileged-adjacent components are realistic and out of the depositor's control.

### Recommendation
Add an explicit refund/cancellation path in `bridge::bridge` for Sui-originated `BridgeRecord`s that remain unapproved (or unclaimed) after a defined timeout, allowing the original sender to reclaim (re-mint, for `MintBurn`-style tokens) their burned amount. At minimum, document that burns are final and irreversible so users are aware of this risk before calling `send_token`, matching the C4 judge's guidance that a refund mechanism should exist unless the sponsor explicitly documents the accepted risk.

### Proof of Concept
1. User calls `bridge::send_token<T>(bridge, target_chain, target_address, coin, ctx)`; this burns `coin` via `treasury.burn` and stores a pending, unsigned `BridgeRecord` [1](#0-0) .
2. Before the bridge client/committee calls `approve_token_transfer` for this message, the destination-chain leg becomes permanently unreachable (e.g., the destination `SuiBridge.sol`/committee is paused or blocklists reach quorum against processing this route, or the off-chain relayer infra is decommissioned).
3. `approve_token_transfer` is never (successfully) called for this `message.key()`; the `BridgeRecord.verified_signatures` remains `option::none()` indefinitely [4](#0-3) .
4. No function in the module (`send_token`, `send_token_v2`, `approve_token_transfer`, `claim_token`, `claim_and_transfer_token`, `execute_system_message`) allows the original sender to recover the burned value [3](#0-2) .
5. Result: the user's tokens are permanently destroyed on Sui with no corresponding unlock ever occurring on the destination chain, and no on-chain refund path exists to make the user whole.

### Citations

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L301-367)
```text
// Record bridge message approvals in Sui, called by the bridge client
// If already approved, return early instead of aborting.
public fun approve_token_transfer(
    bridge: &mut Bridge,
    message: BridgeMessage,
    signatures: vector<vector<u8>>,
) {
    let inner = load_inner_mut(bridge);
    assert!(!inner.paused, EBridgeUnavailable);
    // verify signatures
    inner.committee.verify_signatures(message, signatures);

    assert!(message.message_type() == message_types::token(), EMustBeTokenMessage);
    assert!(
        message.message_version() <= message::token_transfer_message_version(),
        EUnexpectedMessageVersion,
    );
    let token_payload = if (message.message_version() == 2) {
        message.extract_token_bridge_payload_v2().to_token_payload_v1()
    } else {
        message.extract_token_bridge_payload()
    };
    let target_chain = token_payload.token_target_chain();
    assert!(
        message.source_chain() == inner.chain_id || target_chain == inner.chain_id,
        EUnexpectedChainID,
    );

    let message_key = message.key();
    // retrieve pending message if source chain is Sui, the initial message
    // must exist on chain
    if (message.source_chain() == inner.chain_id) {
        let record = &mut inner.token_transfer_records[message_key];

        assert!(record.message == message, EMalformedMessageError);
        assert!(!record.claimed, EInvariantSuiInitializedTokenTransferShouldNotBeClaimed);

        // If record already has verified signatures, it means the message has been approved
        // Then we exit early.
        if (record.verified_signatures.is_some()) {
            event::emit(TokenTransferAlreadyApproved { message_key });
            return
        };
        // Store approval
        record.verified_signatures = option::some(signatures)
    } else {
        // At this point, if this message is in token_transfer_records, we know
        // it's already approved because we only add a message to token_transfer_records
        // after verifying the signatures
        if (inner.token_transfer_records.contains(message_key)) {
            event::emit(TokenTransferAlreadyApproved { message_key });
            return
        };
        // Store message and approval
        inner
            .token_transfer_records
            .push_back(
                message_key,
                BridgeRecord {
                    message,
                    verified_signatures: option::some(signatures),
                    claimed: false,
                },
            );
    };

    event::emit(TokenTransferApproved { message_key });
```

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L610-633)
```text
fun send_token_internal<T>(
    inner: &mut BridgeInner,
    target_chain: u8,
    token: Coin<T>,
    message: BridgeMessage,
) {
    assert!(!inner.paused, EBridgeUnavailable);
    assert!(chain_ids::is_valid_route(inner.chain_id, target_chain), EInvalidBridgeRoute);

    // burn / escrow token, unsupported coins will fail in this step
    inner.treasury.burn(token);

    // Store pending bridge request
    inner
        .token_transfer_records
        .push_back(
            message.key(),
            BridgeRecord {
                message,
                verified_signatures: option::none(),
                claimed: false,
            },
        );
}
```

**File:** crates/sui-framework/published_api.txt (L4972-5010)
```text
create
	fun
	0xb::bridge
init_bridge_committee
	fun
	0xb::bridge
committee_registration
	public fun
	0xb::bridge
update_node_url
	public fun
	0xb::bridge
register_foreign_token
	public fun
	0xb::bridge
send_token
	public fun
	0xb::bridge
send_token_v2
	public fun
	0xb::bridge
approve_token_transfer
	public fun
	0xb::bridge
claim_token
	public fun
	0xb::bridge
claim_and_transfer_token
	public fun
	0xb::bridge
execute_system_message
	public fun
	0xb::bridge
get_token_transfer_action_status
	fun
	0xb::bridge
get_token_transfer_action_signatures
	fun
	0xb::bridge
```
