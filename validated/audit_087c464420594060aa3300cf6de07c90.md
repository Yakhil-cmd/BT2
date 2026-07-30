## Finding

### Title
Bridged tokens become permanently unclaimable if the Sui recipient is added to the token's `DenyList` before `claim_token`/`claim_and_transfer_token` executes - ([File: crates/sui-framework/packages/bridge/sources/bridge.move])

### Summary
The Sui native bridge's `claim_token_internal` mints a bridged `Coin<T>` directly to the `owner` address extracted from the (already-approved, immutable) cross-chain message payload, with no way to redirect or later recover the funds. If `T` is (or later becomes) a regulated coin with a `DenyList` entry (exactly like Circle-issued USDC on Sui, which the bridge is explicitly designed to support — `TOKEN_ID_USDC` is registered via `add_new_token`/`execute_add_tokens_on_sui`), and the recipient address is denied for that coin type between the time the ETH→Sui deposit is approved and the time the claim transaction executes, the claim transaction aborts at the deny-list check and can never succeed for that specific `owner`, because the message's `token_target_address` is baked into the immutable `BridgeRecord` and cannot be changed. This is the direct Move/bridge analog of the reported L1/L2 OP-USDC bridge issue where a blacklisted `_to` address permanently strands bridged funds.

### Finding Description
The claim path is: [1](#0-0) 

Both entry points call the shared internal function that mints from the treasury and computes the immutable recipient from the token payload: [2](#0-1) [3](#0-2) 

The `owner` value is derived once from `token_payload.token_target_address()`, which was fixed at message-creation time on the source chain and is never re-parameterizable by the recipient, by governance, or by any recovery path in this module.

Separately, Sui's regulated-coin deny list is enforced as a mandatory, non-bypassable post-execution check on every written object's owner for coin types that carry a `DenyList` entry: [4](#0-3) [5](#0-4) 

If `owner` is present on the relevant coin's deny list at the current epoch, `result?` at line 2409 causes the whole PTB (and thus the entire claim transaction, including the treasury mint and `record.claimed = true`) to abort. Because the abort is atomic, the `BridgeRecord` is not corrupted, but it is also never marked `claimed`, and the payload's target address is fixed — so **every future retry of `claim_token`/`claim_and_transfer_token` for that `bridge_seq_num` will deterministically abort again** as long as the address stays denied. Bridged tokens support is explicitly meant to include tokens such as USDC: [6](#0-5) [7](#0-6) 

Nothing in `treasury::register_foreign_token`/`add_new_token` prevents registering a regulated `TreasuryCap<T>` (i.e., a coin with an active `DenyCapV2`), and no governance message type in `bridge.move`'s `execute_system_message` provides a way to reroute or cancel a stuck `BridgeRecord` to a different, non-denied address.

### Impact Explanation
This is a direct analog to the reported bug class: value already escrowed/locked/burned on the source chain (Ethereum) becomes permanently unclaimable on the destination chain (Sui) because the sole recipient address encoded in the bridge message is denied on the destination coin, and the bridge module offers no redirect/refund/admin-recovery mechanism. This matches the "permanent fund lock" High-impact category for the Sui bounty scope — the tokens are burned/locked on Ethereum and their Sui-side claim is durably blocked (not a one-time gas-only DoS, but a standing state that can never resolve unless the token issuer/governance separately chooses to unban that specific address for unrelated reasons).

### Likelihood Explanation
Medium-to-High: this requires (a) a bridge-registered coin type on Sui that is deny-listable (a very realistic and intended configuration for a regulated stablecoin like USDC bridged cross-chain, which the bridge test fixtures already anticipate), and (b) the target address becoming denied after the ETH-side deposit/burn but before the Sui-side claim executes — the same "deny-listed mid-flight" race window described in the original report, made worse on Sui by the multi-step approve-then-claim flow and no time bound on when `claim_token`/`claim_and_transfer_token` must be called.

### Recommendation
Add an admin/governance-gated recovery path (mirroring the fixed L1/L2 OP-USDC adapters' `withdrawBlacklistedFunds`) that allows redirecting or refunding a `BridgeRecord` whose `owner` is denied for the claimed coin type — e.g., a system message type that lets the committee re-target a specific `bridge_seq_num`'s recipient, or an escrow/claim-to-anyone-later mechanism that does not hard-code the destination address once assigned. Additionally, consider checking `coin::deny_list_v2_contains_current_epoch`/`_next_epoch` for the recipient before minting and surfacing a distinct, catchable event/return value (similar to `TokenTransferLimitExceed`) so relayers/tools can detect and act on this state rather than repeatedly hitting an execution abort.

### Proof of Concept
1. Governance registers a regulated `Coin<T>` (e.g., a USDC-like coin with `DenyCapV2`) via `add_tokens_on_sui`/`execute_add_tokens_on_sui` (see `bridge::treasury::add_new_token`).
2. User deposits `T` on Ethereum targeting Sui address `BOB` via `SuiBridge.bridgeERC20`; bridge client calls `bridge::approve_token_transfer` on Sui, creating a `BridgeRecord` with `token_target_address = BOB`.
3. Before anyone calls `claim_token`/`claim_and_transfer_token`, the coin issuer (or a compromised/compliance-driven `DenyCapV2` holder) calls `coin::deny_list_v2_add<T>` for `BOB`, and an epoch boundary passes so the denial is active (`deny_list_v2_contains_current_epoch` becomes true).
4. Any caller now invokes `bridge::claim_and_transfer_token<T>(bridge, clock, source_chain, bridge_seq_num, ctx)`. `claim_token_internal` mints `Coin<T>` and `transfer::public_transfer`s it to `BOB`; the post-execution deny-list check in `check_coin_deny_list_v2_during_execution` sees `BOB` as a denied owner for `T` and aborts the entire PTB.
5. `record.claimed` remains `false` and `token_target_address` is immutable, so every subsequent retry of the claim aborts identically. As long as `BOB` remains denied for `T`, the deposited funds are permanently unclaimable on Sui, with no built-in redirect/refund mechanism in `bridge.move`.

### Citations

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L373-407)
```text
public fun claim_token<T>(
    bridge: &mut Bridge,
    clock: &Clock,
    source_chain: u8,
    bridge_seq_num: u64,
    ctx: &mut TxContext,
): Coin<T> {
    let (maybe_token, owner) = bridge.claim_token_internal<T>(
        clock,
        source_chain,
        bridge_seq_num,
        ctx,
    );
    // Only token owner can claim the token
    assert!(ctx.sender() == owner, EUnauthorisedClaim);
    assert!(maybe_token.is_some(), ETokenAlreadyClaimedOrHitLimit);
    maybe_token.destroy_some()
}

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

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L541-567)
```text
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

```

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L600-608)
```text
    // claim from treasury
    let token = inner.treasury.mint<T>(amount, ctx);

    // Record changes
    record.claimed = true;
    event::emit(TokenTransferClaimed { message_key: key });

    (option::some(token), owner)
}
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/execution/context.rs (L2393-2409)
```rust
    // Deny-list v2 checks
    for object in written_objects.values() {
        let coin_type = object.type_().and_then(|ty| ty.coin_type_maybe());
        let owner = object.owner.get_owner_address();
        if let (Some(ty), Ok(owner)) = (coin_type, owner) {
            receiving_funds_type_and_owners
                .entry(ty)
                .or_insert_with(BTreeSet::new)
                .insert(owner);
        }
    }
    let DenyListResult {
        result,
        num_non_gas_coin_owners,
    } = state_view.check_coin_deny_list(receiving_funds_type_and_owners);
    gas_charger.charge_coin_transfers(protocol_config, num_non_gas_coin_owners)?;
    result?;
```

**File:** crates/sui-types/src/deny_list_v2.rs (L142-179)
```rust
/// Returns 1) whether the coin deny list check passed,
///         2) the deny lists checked
///         2) the number of regulated coin owners checked.
pub fn check_coin_deny_list_v2_during_execution(
    receiving_funds_type_and_owners: BTreeMap<TypeTag, BTreeSet<SuiAddress>>,
    cur_epoch: EpochId,
    object_store: &dyn ObjectStore,
) -> DenyListResult {
    let non_gas_coin_owners = receiving_funds_type_and_owners
        .into_iter()
        .filter_map(|(ty, owners)| {
            if GAS::is_gas_type(&ty) {
                None
            } else {
                Some((ty.to_canonical_string(false), owners))
            }
        })
        .collect::<BTreeMap<_, _>>();
    let num_non_gas_coin_owners = non_gas_coin_owners.values().map(|v| v.len() as u64).sum();
    let regulated_coin_owners = non_gas_coin_owners
        .into_iter()
        .filter_map(|(coin_type, owners)| {
            let deny_list_config = get_per_type_coin_deny_list_v2(&coin_type, object_store)?;
            Some((coin_type, (deny_list_config, owners)))
        })
        .collect::<BTreeMap<_, _>>();
    let result = check_new_regulated_coin_owners(regulated_coin_owners, cur_epoch, object_store);
    // `num_non_gas_coin_owners` is used to charge for gas. As such we must be extremely careful
    // to not use a number that is not consistent across all validators. For example, relying on
    // the number of coins with a deny list is _not_ consistent since the deny list is created
    // on the first addition to the deny list. But the total number of coins/owners denied would
    // be consistent since we rely on the results from the last epoch (i.e. relying on the Config's
    // internal invariants)
    DenyListResult {
        result,
        num_non_gas_coin_owners,
    }
}
```

**File:** crates/sui-bridge/src/e2e_tests/test_utils.rs (L1075-1084)
```rust
            let token_ids = vec![TOKEN_ID_BTC, TOKEN_ID_ETH, TOKEN_ID_USDC, TOKEN_ID_USDT];
            let token_prices = vec![500_000_000u64, 30_000_000u64, 1_000u64, 1_000u64];
            let action = publish_and_register_coins_return_add_coins_on_sui_action(
                test_cluster.wallet(),
                bridge_arg,
                vec![
                    Path::new("../../bridge/move/tokens/btc").into(),
                    Path::new("../../bridge/move/tokens/eth").into(),
                    Path::new("../../bridge/move/tokens/usdc").into(),
                    Path::new("../../bridge/move/tokens/usdt").into(),
```

**File:** crates/sui-framework/packages/bridge/sources/treasury.move (L122-161)
```text
public(package) fun add_new_token(
    self: &mut BridgeTreasury,
    token_name: String,
    token_id: u8,
    native_token: bool,
    notional_value: u64,
) {
    if (!native_token) {
        assert!(notional_value > 0, EInvalidNotionalValue);
        let ForeignTokenRegistration {
            type_name,
            uc,
            decimal,
        } = self.waiting_room.remove<String, ForeignTokenRegistration>(token_name);
        let decimal_multiplier = 10u64.pow(decimal);
        self
            .supported_tokens
            .insert(
                type_name,
                BridgeTokenMetadata {
                    id: token_id,
                    decimal_multiplier,
                    notional_value,
                    native_token,
                },
            );
        self.id_token_type_map.insert(token_id, type_name);

        // Freeze upgrade cap to prevent changes to the coin
        transfer::public_freeze_object(uc);

        event::emit(NewTokenEvent {
            token_id,
            type_name,
            native_token,
            decimal_multiplier,
            notional_value,
        })
    } // else not implemented in V1
}
```
