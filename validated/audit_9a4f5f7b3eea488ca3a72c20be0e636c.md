### Title
Bridge token claims permanently lock funds when recipient is on the coin deny list - ([File: crates/sui-framework/packages/bridge/sources/bridge.move])

### Summary
The Sui native bridge's `claim_token`/`claim_and_transfer_token` flow mints/transfers a bridged coin to a fixed recipient address embedded in the original signed bridge message, and marks the transfer record as `claimed = true` in the same atomic transaction. If that coin type is a deny-listed ("regulated") coin and the recipient address is on the coin's deny list at claim time, the post-execution deny-list check aborts the *entire* transaction — reverting the `record.claimed = true` write along with everything else. Because the recipient address is immutably fixed in the bridge message and there is no override/redirect/cancel path, every future claim attempt for that message will deterministically hit the same abort, permanently locking the bridged funds. This mirrors the reported ERC20 bug class exactly: a genuine, foreseeable external-transfer failure (blacklist/deny) that is allowed to abort a state-critical function with no fallback "balance-then-withdraw" or "clearBid"-style recovery mechanism.

### Finding Description
`claim_token_internal` in `crates/sui-framework/packages/bridge/sources/bridge.move` (lines ~521-608) derives the recipient `owner` from the immutable, committee-signed `BridgeMessage` payload (`token_payload.token_target_address()`), then:
- Checks the bridge limiter,
- Mints the coin from the treasury (`inner.treasury.mint<T>(amount, ctx)`),
- Sets `record.claimed = true`,
- Emits `TokenTransferClaimed`. [1](#0-0) [2](#0-1) 

`claim_and_transfer_token` (callable by anyone) additionally does `transfer::public_transfer(token.destroy_some(), owner)` in the same transaction: [3](#0-2) 

Separately, `claim_token` returns the raw `Coin<T>` to the caller with `assert!(ctx.sender() == owner, EUnauthorisedClaim)`; the coin object still ends the PTB owned by that same denied address, since only the legitimate owner can call it and, absent further routing in the same PTB, retains ownership.

Sui's execution pipeline performs a **post-execution** coin deny-list check over all newly-written coin objects' owners, and if any owner is denied for that coin type, the whole execution is treated as a failure (only gas is charged; all other object mutations, including `record.claimed = true`, are discarded): [4](#0-3) [5](#0-4) 

This behavior is demonstrated in transactional tests, where a denied receiver causes the transaction to abort with `AddressDeniedForCoin` and effects show only the gas object mutated (state changes rolled back): [6](#0-5) 

The bridge module has no mechanism to redirect the claim to a different address, cancel the pending transfer, or let governance reroute/refund it — I found no `refund`, `cancel`, or address-override function in the bridge sources (`grep` for these terms in bridge-related files returned no matches).

### Impact Explanation
If the bridged token type `T` is a Sui regulated coin (deny-list v2 enabled) and the fixed target address becomes deny-listed for that coin type *before* the bridge claim is executed (a realistic, foreseeable "genuine reason" exactly as flagged in the original report), then:
- Every call to `claim_token` or `claim_and_transfer_token` for that `bridge_seq_num` will deterministically abort with `AddressDeniedForCoin`.
- `record.claimed` never becomes `true` because the abort discards all execution effects except gas charges.
- The bridged value can never be claimed by anyone, and there is no alternate path (no admin override, no refund-to-source-chain, no re-targeting) in the Move module to recover it.

This is a permanent loss of access to bridged principal, matching the explicitly allowed High-severity impact class: "permanent fund lock." It does not require a malicious validator, bridge authority, or governance quorum — only an ordinary (if privileged over their own coin) regulated-coin issuer performing a routine compliance action, and an ordinary bridge user whose funds happen to be in flight to that address.

### Likelihood Explanation
Moderate. It requires: (1) a bridge-supported token type that is also a Sui deny-list-v2 regulated coin, and (2) the target address becoming deny-listed between the time a bridge deposit is initiated on the source chain and the time the claim transaction executes on Sui — a realistic time window given the bridge's approval/claim flow takes multiple asynchronous steps (signature aggregation, orchestrator submission). Deny-listing is a normal compliance action already built into the coin standard, not an exotic edge case, so the trigger condition is entirely plausible in production once a regulated stablecoin is bridge-supported.

### Recommendation
- Do not let a failed downstream transfer/deny-list check block the bridge's own bookkeeping. Separate "mark claimed / consume the bridge record" from "deliver funds to the recipient," following the pattern recommended in the original report: use an internal balance/escrow mechanism (e.g., record an entitlement for the recipient) so a temporarily-undeliverable transfer does not prevent the bridge record from being finalized.
- Add a `redirect`/`reclaim` path (e.g., allow the legitimate claimant, once un-denied or via a governance system message, to redirect the entitlement to an alternate address) so funds are not permanently stranded.
- Alternatively, if a claim would fail due to the coin's deny-list state, catch this deterministically before minting/transferring (query deny-list status via a view function prior to mutating state) and emit an event/return an option rather than aborting the entire transaction — while still leaving a permanent record for later reclamation once the block-list state changes.

### Proof of Concept
Conceptual sequence (cannot be executed without a live devnet, but derivable directly from the code paths above):
1. Coin `T` is registered on the bridge and is a Sui `create_regulated_currency_v2` coin with an active `DenyCapV2`.
2. User deposits `T` on Ethereum via `SuiBridge.bridgeERC20`, targeting Sui address `R`.
3. Bridge validators sign the message; client calls `bridge::approve_token_transfer`, creating a `BridgeRecord` with `claimed = false` and `token_target_address = R`.
4. Before anyone claims, the coin issuer calls `coin::deny_list_v2_add<T>(deny_list, deny_cap, R, ctx)` (a routine compliance action) and an epoch boundary passes so the deny entry is enforced for receiving.
5. Anyone calls `bridge::claim_and_transfer_token<T>(bridge, clock, source_chain, bridge_seq_num, ctx)` (or `R` itself calls `claim_token`). Execution mints the coin and attempts to leave/transfer it to `R`.
6. Post-execution deny-list check (`check_coin_deny_list_v2_during_execution` → `AddressDeniedForCoin`) aborts the transaction; effects show only gas charged, `record.claimed` remains `false` (per the pattern shown in `coin_deny_and_undeny_address_balance_receiver.snap` lines 51-56).
7. Every subsequent claim attempt for this `bridge_seq_num` repeats step 6 forever, as there is no code path to alter `R`, refund the sender, or force-settle the record — the bridged value is permanently locked.

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

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L559-566)
```text
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

**File:** crates/sui-types/src/deny_list_v2.rs (L145-168)
```rust
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
```

**File:** crates/sui-adapter-transactional-tests/tests/deny_list_v2/coin_deny_and_undeny_address_balance_receiver.snap (L51-56)
```text
task 7, lines 63-65:
//# programmable --sender A --inputs object(1,5) 1 @B
//> 0: test::regulated_coin::split_to_balance(Input(0), Input(1));
//> 1: sui::balance::send_funds<test::regulated_coin::REGULATED_COIN>(Result(0), Input(2));
Error: Transaction Effects Status: Address B is denied for coin test::regulated_coin::REGULATED_COIN
Execution Error: ExecutionError: ExecutionError { inner: ExecutionErrorInner { kind: AddressDeniedForCoin { address: B, coin_type: "test::regulated_coin::REGULATED_COIN" }, source: None, command: None } }
```
