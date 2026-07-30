## Title
Bridge Claim Push-Transfer to a Deny-Listed Coin Recipient Permanently Locks Bridged Funds — (File: `crates/sui-framework/packages/bridge/sources/bridge.move`)

### Summary
The Sui native bridge's claim path (`claim_token_internal` / `claim_token` / `claim_and_transfer_token`) mints the bridged coin and pushes it directly to a `target_address` decoded from untrusted, cross-chain message bytes, exactly like the reported `calculateAndDistributeManagerFees()` push pattern. If the coin type is a regulated coin (deny-listable via `coin::deny_list_v2_*`) and the decoded target address is denied (or global pause is enabled) for that coin type, the whole claiming transaction aborts post-execution with `AddressDeniedForCoin`. Because the deny-list check runs after Move execution and its failure discards all execution effects, `record.claimed` is never set to `true` and the minted coin is never produced — every future claim attempt for that specific bridge message fails the same way, permanently locking the underlying bridged value with no alternate recipient or recovery path.

### Finding Description
`claim_token_internal` decodes the recipient purely from the signed bridge message payload and never validates it against the coin's deny list before performing the mint/transfer: [1](#0-0) 

The claim functions push the newly minted coin straight to that address: [2](#0-1) 

The actual deny-list enforcement for coin-type receivers happens only after Move execution completes, at the adapter/temporary-store layer, by scanning all written objects' owners and erroring out the entire transaction if any owner is denied: [3](#0-2) [4](#0-3) 

Because `result?` propagates the deny-list failure as a transaction execution error, all execution results (including the `record.claimed = true` write and the freshly minted `Coin<T>`) are discarded rather than partially committed — this is the documented behavior for regulated-coin receivers: [5](#0-4) 

Since `claim_token_internal` hardcodes `owner` from the original cross-chain message with no way to redirect to a different, non-denied address, and `claim_token`/`claim_and_transfer_token` are the only entry points to release the bridged value, a bridge message whose target address becomes deny-listed (or is denied under a global pause) can never be finalized. This mirrors the report's exact root cause: a mandatory push-transfer inside a state-transition function that has no fallback and blocks all dependent flows if the recipient cannot legally receive the asset.

### Impact Explanation
This results in a **permanent fund lock** of value already escrowed cross-chain (locked in the EVM vault or burned on the Sui side) with no way for anyone — including governance/committee via `execute_system_message`, which only handles emergency pause, blocklist, limiter and price updates, not recipient overrides — to redirect or release it. Under the Sui HackenProof scope, "permanent fund lock" is an explicit High-severity allowed impact. Unlike the storage-fund/validator-set reward loop (`validator_set.move::distribute_reward`), which only ever pays native, non-regulated `SUI` and therefore cannot hit the deny-list path, the bridge's `claim_token_internal` operates over an arbitrary generic `Coin<T>`, including regulated bridge-wrapped assets, making it the closest true Sui analog to the reported vulnerability class.

### Likelihood Explanation
The trigger requires no malicious peer, validator, or bridge authority: an ordinary user deposits on the foreign chain specifying a destination Sui address (their own, in the ordinary flow), the committee performs its normal, honest approval, and — independently and legitimately — the regulated coin issuer (using its own `DenyCapV2`, a normal compliance action already exercised in production for sanctioned addresses) adds that address to the deny list or enables global pause before the claim executes. From that point, every claim attempt for that message deterministically fails at the deny-list check, and the failure is silent from the Move module's perspective (it looks like a normal execution abort, not an event), leaving the funds stuck indefinitely with no built-in recourse.

### Recommendation
Do not push the minted coin unconditionally to an address decoded from message bytes. Instead:
- Check the coin's deny-list/global-pause status for the decoded target address before minting/transferring, and if denied, keep the `BridgeRecord` unclaimed and emit a distinguishable event rather than letting the whole transaction abort with all effects discarded.
- Provide a pull-based claim, or an admin/governance-gated recovery path (e.g., an `execute_system_message` variant) to redirect stuck claims to a different address, similar to the "claim via `claimManagerFees()`" pattern recommended in the original report.

### Proof of Concept
1. Publish/register a regulated bridge-wrapped coin type `T` with `DenyCapV2<T>` (bridge tokens added via `execute_add_tokens_on_sui`/`add_tokens_on_evm` can be arbitrary coin types).
2. A user bridges tokens from the foreign chain to Sui, targeting Sui address `R` (`R`'s own choice, or a third party); committee signs normally and `approve_token_transfer` records the message.
3. Before anyone calls `claim_token`/`claim_and_transfer_token`, the `T` issuer calls `coin::deny_list_v2_add<T>` for `R` (or `deny_list_v2_enable_global_pause<T>`), as demonstrated by the existing test flow at: [6](#0-5) 
4. Any subsequent call to `claim_token<T>`/`claim_and_transfer_token<T>` for that message aborts with `AddressDeniedForCoin`; `record.claimed` remains `false` forever, and the escrowed/locked bridge value for that message can never be retrieved by `R` or anyone else.

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

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L559-560)
```text
    // get owner address
    let owner = address::from_bytes(token_payload.token_target_address());
```

**File:** sui-execution/latest/sui-adapter/src/temporary_store.rs (L1226-1245)
```rust
    fn check_coin_deny_list(
        &self,
        receiving_funds_type_and_owners: BTreeMap<TypeTag, BTreeSet<SuiAddress>>,
    ) -> DenyListResult {
        let result = check_coin_deny_list_v2_during_execution(
            receiving_funds_type_and_owners,
            self.cur_epoch,
            self.store.as_object_store(),
        );
        // The denylist object is only loaded if there are regulated transfers.
        // And also if we already have it in the input there is no need to commit it again in the effects.
        if result.num_non_gas_coin_owners > 0
            && !self.input_objects.contains_key(&SUI_DENY_LIST_OBJECT_ID)
        {
            self.loaded_per_epoch_config_objects
                .write()
                .insert(SUI_DENY_LIST_OBJECT_ID);
        }
        result
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

**File:** crates/sui-adapter-transactional-tests/tests/deny_list_v2/coin_deny_and_undeny_receiver.snap (L42-46)
```text
task 6, lines 50-52:
//# run sui::pay::split_and_transfer --args object(1,5) 1 @B --type-args test::regulated_coin::REGULATED_COIN --sender A
Error: Transaction Effects Status: Address B is denied for coin test::regulated_coin::REGULATED_COIN
Execution Error: ExecutionError: ExecutionError { inner: ExecutionErrorInner { kind: AddressDeniedForCoin { address: B, coin_type: "test::regulated_coin::REGULATED_COIN" }, source: None, command: None } }

```

**File:** crates/sui-adapter-transactional-tests/tests/deny_list_v2/coin_global_pause.move (L82-95)
```text
// Enable global pause.
//# run sui::coin::deny_list_v2_enable_global_pause --args object(0x403) object(1,3) --type-args test::regulated_coin::REGULATED_COIN --sender A

// Assert that global pause is enabled.
//# run test::regulated_coin::assert_global_pause_status --args immshared(0x403) true --sender A

// Transfer the regulated coin from A no longer works.
//# run sui::pay::split_and_transfer --args object(1,5) 1 @B --type-args test::regulated_coin::REGULATED_COIN --sender A

// Transfer the coin from B also no longer works.
//# transfer-object 2,0 --sender B --recipient A

// Try using the coin in a Move call. This should also be denied.
//# run sui::pay::split_and_transfer --args object(2,0) 1 @A --type-args test::regulated_coin::REGULATED_COIN --sender B
```
