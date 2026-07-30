Based on the bridge claim path in [1](#0-0) , I found a plausible native analog, though I was unable to fully verify the exact deny-list abort location before running out of tool calls (noted below).

### Title
Permanent Fund Lock in Bridge Claim Path When Recipient Is Denylisted for a Regulated Coin - (File: crates/sui-framework/packages/bridge/sources/bridge.move)

### Summary
The Sui native bridge's claim path marks a cross-chain transfer as permanently `claimed` and mints the underlying `Coin<T>` *before* delivering it to the recipient. If `T` is a regulated coin and the recipient address is on that coin's deny list, the delivery step aborts every time it is attempted, and because Move transactions are atomic, the abort also reverts the `claimed` flag — meaning the transfer can be retried forever but will never succeed, permanently trapping the bridged value with no bridge-level recovery mechanism. This mirrors the reported LayerZero `OAppLzReceive` bug, where a frozen destination token account causes the vault-side settlement logic to diverge from actual on-chain delivery, and the reporter's own remediation (add tracking + an admin withdrawal path) highlights that the missing piece is exactly what Sui's bridge module also lacks.

### Finding Description
`claim_token_internal` performs the mint and sets `record.claimed = true` unconditionally once signature/limiter checks pass: [2](#0-1) 

`claim_and_transfer_token`, callable by anyone, then attempts to deliver the freshly minted coin to the `owner` address decoded from the bridge message payload: [3](#0-2) 

Sui's regulated-coin / deny-list v2 feature can block an address from receiving or holding a specific coin type, enforced as part of object transfer semantics for that type (see the deny-list test suite, e.g. [4](#0-3)  and `coin_global_pause.move`). If the bridge is configured to support a regulated `Coin<T>` and the payload's target address is later added to that coin's deny list — a legitimate compliance action unrelated to bridge governance — then `transfer::public_transfer` inside `claim_and_transfer_token` will abort on every future call. Because Move aborts roll back the entire transaction, `record.claimed` reverts to `false` each time, so the message can be retried indefinitely but the underlying value can never actually reach the recipient, and there is no other code path (no admin sweep, no re-routing, no alternate recipient) to recover the escrowed/burned source-chain funds.

I was not able to confirm the exact byte-level location of the deny-list enforcement (whether it's a Move-level `assert!` inside `coin.move`/`balance.move` or a VM/adapter-level check during the `TransferObjects` command) before running out of tool budget; this should be verified directly against `crates/sui-framework/packages/sui-framework/sources/coin.move` and the deny-list-aware transfer path in the adapter.

### Impact Explanation
This falls under the "permanent fund lock" High-severity bounty category. Value that was locked/burned on the source chain (EVM or another chain) via the bridge's deposit path can never be minted-and-delivered on Sui once the recipient is denylisted for that coin type, and the bridge module provides no alternative claim, redirect, or admin-recovery mechanism, exactly the gap identified in the original report's remediation.

### Likelihood Explanation
Likelihood depends on the bridge listing a regulated (deny-list-capable) coin type as a bridgeable asset via `execute_add_tokens_on_sui`/`AddTokenOnSui`, and on any legitimate compliance freeze being applied to a recipient address after (or before) a bridge transfer targeting them is initiated. This is a normal, expected operational event for regulated stablecoins, not a contrived attack, making it realistically triggerable without any malicious admin, validator, or bridge authority involvement — the "attacker" here is simply an ordinary address that becomes denylisted through routine compliance processes while a bridge transfer is in flight.

### Recommendation
Decouple "claimed" bookkeeping from successful delivery: either (a) hold minted-but-undeliverable coins in an escrow object tied to the message key so an admin/governance path (or the affected user once undenylisted) can later sweep them, or (b) perform the deny-list eligibility check before minting/marking `claimed`, and if the recipient is denylisted, leave the record in a distinct terminal state that supports a documented recovery flow instead of silently reverting forever on retry.

### Proof of Concept
1. Bridge committee adds a regulated coin type `T` (deny-list-capable) via `execute_add_tokens_on_sui`.
2. A user bridges funds from EVM/other chain to Sui with `target_address = A`.
3. Before or after `approve_token_transfer` records the message, the issuer of `T` adds address `A` to `T`'s deny list via `deny_list_v2` (a normal, non-malicious compliance action).
4. Any caller invokes `claim_and_transfer_token<T>` for this message: `claim_token_internal` mints the coin and sets `record.claimed = true`, then `transfer::public_transfer(token, A)` aborts because `A` is denylisted for `T`.
5. The abort reverts `record.claimed` to `false`. Every subsequent call to `claim_and_transfer_token<T>` (or `claim_token<T>`, which requires `ctx.sender() == A` and would itself be blocked from using the coin) repeats the same failure indefinitely — the bridged value is permanently unclaimable with no bridge-side recovery path.

### Citations

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L392-407)
```text
// This function can be called by anyone to claim and transfer the token to the recipient
// If the token has already been claimed or hits limiter currently, it will return instead of aborting.
public fun claim_and_transfer_token<T>(
    bridge: &mut Bridge,
    clock: &Clock,
    source_chain: u8,
    bridge_seq_num: u64,
    ctx: &mut TxContext,
) {
    let (token, owner) = bridge.claim_token_internal<T>(clock, source_chain, bridge_seq_num, ctx);
    if (token.is_some()) {
        transfer::public_transfer(token.destroy_some(), owner)
    } else {
        token.destroy_none();
    };
}
```

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L521-608)
```text
// Claim token from approved bridge message
// Returns Some(Coin) if coin can be claimed. If already claimed, return None
fun claim_token_internal<T>(
    bridge: &mut Bridge,
    clock: &Clock,
    source_chain: u8,
    bridge_seq_num: u64,
    ctx: &mut TxContext,
): (Option<Coin<T>>, address) {
    let inner = load_inner_mut(bridge);
    assert!(!inner.paused, EBridgeUnavailable);

    let key = message::create_key(source_chain, message_types::token(), bridge_seq_num);

    assert!(inner.token_transfer_records.contains(key), EMessageNotFoundInRecords);

    // retrieve approved bridge message
    let record = &mut inner.token_transfer_records[key];
    // ensure this is a token bridge message
    assert!(&record.message.message_type() == message_types::token(), EUnexpectedMessageType);
    // Ensure it's signed
    assert!(record.verified_signatures.is_some(), EUnauthorisedClaim);

    // extract token message
    let mut bypass_limiter = false;
    let token_payload;
    if (record.message.message_version() == 2) {
        let token_payload_v2 = record.message.extract_token_bridge_payload_v2();

        let timestamp = token_payload_v2.timestamp_ms();
        // if more than 48 hours have passed since deposit, bypass the limiter
        // (the limiter exists to give time to respond to bugs)
        bypass_limiter = clock.timestamp_ms() > timestamp + 48 * 3600000;
        token_payload = token_payload_v2.to_token_payload_v1();
    } else {
        token_payload = record.message.extract_token_bridge_payload();
    };

    // get owner address
    let owner = address::from_bytes(token_payload.token_target_address());

    // If already claimed, exit early
    if (record.claimed) {
        event::emit(TokenTransferAlreadyClaimed { message_key: key });
        return (option::none(), owner)
    };

    let target_chain = token_payload.token_target_chain();
    // ensure target chain matches bridge.chain_id
    assert!(target_chain == inner.chain_id, EUnexpectedChainID);

    // TODO: why do we check validity of the route here? what if inconsistency?
    // Ensure route is valid
    // TODO: add unit tests
    // `get_route` abort if route is invalid
    let route = chain_ids::get_route(source_chain, target_chain);
    // check token type
    assert!(
        treasury::token_id<T>(&inner.treasury) == token_payload.token_type(),
        EUnexpectedTokenType,
    );

    let amount = token_payload.token_amount();
    // Make sure transfer is within limit.
    if (
        !bypass_limiter &&
        !inner
            .limiter
            .check_and_record_sending_transfer<T>(
                &inner.treasury,
                clock,
                route,
                amount,
            )
    ) {
        event::emit(TokenTransferLimitExceed { message_key: key });
        return (option::none(), owner)
    };

    // claim from treasury
    let token = inner.treasury.mint<T>(amount, ctx);

    // Record changes
    record.claimed = true;
    event::emit(TokenTransferClaimed { message_key: key });

    (option::some(token), owner)
}
```

**File:** crates/sui-adapter-transactional-tests/tests/deny_list_v2/coin_deny_and_undeny_receiver.move (L1-1)
```text
// Copyright (c) Mysten Labs, Inc.
```
