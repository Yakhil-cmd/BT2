## Finding

### Title
Sui Bridge Token Claims Permanently Lock Funds When Recipient Is Coin‑Deny‑Listed - (File: `crates/sui-framework/packages/bridge/sources/bridge.move`)

### Summary
The Sui native bridge's `claim_token_internal` mints a bridged coin and unconditionally transfers it to the `target_address` embedded in the original (already-burned-on-source-chain) `BridgeMessage`, with no check against the Sui `coin::deny_list_v2` for that coin type. If the destination coin type `T` registered on the bridge is a regulated coin and the intended recipient becomes deny-listed (at any time, by the coin's own `DenyCapV2` holder — independent of the bridge committee), the transaction that mints and transfers the coin aborts at the very end of PTB execution with `AddressDeniedForCoin`. Because the abort rolls back the whole transaction (including `record.claimed = true`), the claim can be retried forever and will always fail as long as the recipient remains denied, permanently locking the already-escrowed/burned source-chain funds. This mirrors the external report's root cause: the "blacklist"/deny-list check that gates delivery is evaluated only on the destination chain at credit time, with no fallback like `StakedUSDeOFTAdapter`'s "credit owner instead of reverting" mitigation.

### Finding Description
`claim_token_internal` in `crates/sui-framework/packages/bridge/sources/bridge.move` derives the recipient purely from message data and mints funds to it: [1](#0-0) 

`claim_token`/`claim_and_transfer_token` then do `transfer::public_transfer(token, owner)` in the same PTB: [2](#0-1) 

There is no code path anywhere in `bridge.move`, `treasury.move`, or `limiter.move` that consults `sui::coin::DenyList`/`deny_list_v2` before minting/transferring to the recipient. Instead, the deny-list enforcement happens generically at the very end of transaction execution, by scanning all written coin objects and their owners: [3](#0-2) [4](#0-3) 

If the owner is denied, the whole transaction execution errors out with `AddressDeniedForCoin`, which aborts and reverts **all** effects of that transaction: [5](#0-4) 

Because the abort discards state changes, `BridgeRecord.claimed` is never persisted as `true`; the record is stuck as claimable-but-unclaimable forever. `register_foreign_token`/`treasury::mint` place no restriction preventing a regulated (`DenyCapV2`-bearing) coin type from being bridged: [6](#0-5) [7](#0-6) 

The target address is fully attacker/user-controlled at deposit time on the EVM side (`bridgeERC20`/`bridgeETH` take an arbitrary `recipientAddress`), and the deposit is finalized (tokens locked/burned) before the destination-chain deny status is ever evaluated: [8](#0-7) 

This exactly matches the external report's "inconsistency in blacklisted addresses treatment": the source chain has no visibility into destination-chain deny/blacklist state, so a transfer that was valid at initiation becomes permanently undeliverable at settlement — except here, Sui's bridge has no `StakedUSDeOFTAdapter`-style fallback (reroute to `owner()`), so the result is a hard permanent lock rather than a redirect.

### Impact Explanation
This produces **permanent fund lock**: bridged funds are burned/escrowed on the source chain, but the Sui-side claim can never succeed for a deny-listed recipient because every retry deterministically aborts the whole transaction (deny-list membership is independent of, and outlives, bridge state). This falls squarely into the explicitly listed impact category "permanent fund lock... reachable from public input" (High/Medium per the program scope), triggered purely by an ordinary bridge user's deposit plus an independent regulated-coin issuer's routine deny-list action — neither of which is a bridge authority, validator, or governance quorum action.

### Likelihood Explanation
Reachable by any unprivileged bridge user: they simply need to bridge a regulated/foreign token to an address that is (or later becomes) deny-listed by that token's own `DenyCapV2` holder. This can happen accidentally (a legitimate recipient gets sanctioned/denied after depositing but before claiming) or be induced deliberately by anyone able to influence deny-list decisions for a registered bridge token (e.g., a stablecoin issuer who is a completely separate party from the bridge committee). No malicious validator, bridge authority, or governance quorum is required — only a routine deny-list update by the coin's legitimate compliance operator.

### Recommendation
Mirror the EVM `StakedUSDeOFTAdapter` mitigation: in `claim_token_internal`/`claim_and_transfer_token`, check `coin::deny_list_v2_contains_current_epoch` (or the equivalent read) for the resolved `owner` before minting/transferring, and if denied, mint/transfer to a designated fallback address (e.g., bridge treasury/owner) or otherwise persist the claim in a recoverable state instead of allowing a global, unconditional abort that erases `record.claimed` and blocks all future retries.

### Proof of Concept
1. Governance registers a regulated coin `T` (created via `coin::create_regulated_currency_v2`, i.e., has a `DenyCapV2<T>`) as a supported bridge token via `execute_add_tokens_on_sui`.
2. An ordinary EVM user calls `SuiBridge.bridgeERC20(tokenID_T, amount, recipientAddress = R, destinationChainID = SUI)`, locking funds in the EVM vault; `R` is any Sui address chosen by the depositor.
3. Before the bridge relayers process the claim, the `DenyCapV2<T>` holder (unrelated to bridge committee) calls `coin::deny_list_v2_add<T>(deny_list, deny_cap, R, ctx)`, and an epoch boundary passes so the deny entry is active for `R`.
4. Anyone calls `bridge::claim_and_transfer_token<T>(bridge, clock, source_chain, seq_num, ctx)`. `claim_token_internal` mints the coin and `transfer::public_transfer` sends it to `R`; at PTB finalization, `check_coin_deny_list` detects `R` is denied and the whole transaction aborts with `AddressDeniedForCoin`.
5. Retry indefinitely: the transaction always aborts the same way because `R`'s deny status is independent of bridge state, so `BridgeRecord.claimed` never becomes `true`. The bridged funds (already burned on EVM) are permanently unclaimable.

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

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L559-608)
```text
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

**File:** sui-execution/v3/sui-adapter/src/programmable_transactions/context.rs (L1574-1595)
```rust
        if protocol_config.enable_coin_deny_list_v2() {
            for object in written_objects.values() {
                let coin_type = object.type_().and_then(|ty| ty.coin_type_maybe());
                let owner = if protocol_config.use_coin_party_owner() {
                    object.owner.get_owner_address()
                } else {
                    object.owner.get_address_owner_address()
                };
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
        }
```

**File:** crates/sui-types/src/deny_list_v2.rs (L181-206)
```rust
fn check_new_regulated_coin_owners(
    new_regulated_coin_owners: BTreeMap<String, (Config, BTreeSet<SuiAddress>)>,
    cur_epoch: EpochId,
    object_store: &dyn ObjectStore,
) -> Result<(), ExecutionError> {
    for (coin_type, (deny_list, owners)) in new_regulated_coin_owners {
        if check_global_pause(&deny_list, object_store, Some(cur_epoch)) {
            return Err(ExecutionError::new(
                ExecutionErrorKind::CoinTypeGlobalPause { coin_type },
                None,
            ));
        }
        for owner in owners {
            if check_address_denied_by_config(&deny_list, owner, object_store, Some(cur_epoch)) {
                return Err(ExecutionError::new(
                    ExecutionErrorKind::AddressDeniedForCoin {
                        address: owner,
                        coin_type,
                    },
                    None,
                ));
            }
        }
    }
    Ok(())
}
```

**File:** crates/sui-types/src/execution_status.rs (L261-265)
```rust
    #[error("Address {address:?} is denied for coin {coin_type}")]
    AddressDeniedForCoin {
        address: SuiAddress,
        coin_type: String,
    },
```

**File:** crates/sui-framework/packages/bridge/sources/treasury.move (L90-120)
```text
public(package) fun register_foreign_token<T>(
    self: &mut BridgeTreasury,
    tc: TreasuryCap<T>,
    uc: UpgradeCap,
    metadata: &CoinMetadata<T>,
) {
    // Make sure TreasuryCap has not been minted before.
    assert!(coin::total_supply(&tc) == 0, ETokenSupplyNonZero);
    let type_name = type_name::with_defining_ids<T>();
    let address_bytes = hex::decode(ascii::into_bytes(type_name::address_string(&type_name)));
    let coin_address = address::from_bytes(address_bytes);
    // Make sure upgrade cap is for the Coin package
    // FIXME: add test
    assert!(
        object::id_to_address(&package::upgrade_package(&uc)) == coin_address,
        EInvalidUpgradeCap,
    );
    let registration = ForeignTokenRegistration {
        type_name,
        uc,
        decimal: coin::get_decimals(metadata),
    };
    self.waiting_room.add(type_name::into_string(type_name), registration);
    self.treasuries.add(type_name, tc);

    event::emit(TokenRegistrationEvent {
        type_name,
        decimal: coin::get_decimals(metadata),
        native_token: false,
    });
}
```

**File:** crates/sui-framework/packages/bridge/sources/treasury.move (L172-180)
```text
public(package) fun burn<T>(self: &mut BridgeTreasury, token: Coin<T>) {
    let treasury = &mut self.treasuries[type_name::with_defining_ids<T>()];
    coin::burn(treasury, token);
}

public(package) fun mint<T>(self: &mut BridgeTreasury, amount: u64, ctx: &mut TxContext): Coin<T> {
    let treasury = &mut self.treasuries[type_name::with_defining_ids<T>()];
    coin::mint(treasury, amount, ctx)
}
```

**File:** bridge/evm/contracts/SuiBridge.sol (L135-150)
```text
    function bridgeERC20(
        uint8 tokenID,
        uint256 amount,
        bytes memory recipientAddress,
        uint8 destinationChainID
    ) external whenNotPaused nonReentrant onlySupportedChain(destinationChainID) {
        require(
            recipientAddress.length == SUI_ADDRESS_LENGTH,
            "SuiBridge: Invalid recipient address length"
        );

        IBridgeConfig config = committee.config();

        require(config.isTokenSupported(tokenID), "SuiBridge: Unsupported token");

        address tokenAddress = config.tokenAddressOf(tokenID);
```
