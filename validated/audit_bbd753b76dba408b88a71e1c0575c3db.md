### Title
Duplicate collateral legs double-count one `flash_position` callback receipt - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary
`flash_position` snapshots collateral balances by token `Address`, but later evaluates every submitted `(HubAssetKey, min_amount)` leg independently against that shared snapshot. An attacker can submit the same token under two different `hub_id` markets, transfer the token once during the receiver callback, and have the same balance delta deposited into both markets. [1](#0-0) [2](#0-1) 

### Finding Description
The permissionless `flash_position` entrypoint accepts caller-selected `collaterals` and a Wasm receiver callback. [3](#0-2)  It mints and forwards the debt before invoking the receiver. [4](#0-3) [5](#0-4) 

Before the callback, the controller snapshots each collateral token once by `Address`. [6](#0-5)  `snapshot_balances` intentionally deduplicates repeated token addresses, so one baseline represents every hub market using that token. [1](#0-0) 

After the callback, `collect_collateral_deposits` iterates all collateral legs, looks up the baseline by `hub_asset.asset`, recomputes the same post-callback balance delta for each leg, and pushes each leg into `deposits`. [2](#0-1)  Consequently, `[(HubAssetKey { hub_id: 0, asset: X }, min), (HubAssetKey { hub_id: 1, asset: X }, min)]` converts one receipt of `X` into two separate supply deposits.

### Impact Explanation
The attacker receives credited supply shares in multiple `(hub, token)` books while only one physical token amount entered custody. Those shares can support a larger flash-position debt or later be redeemed, leaving the protocol with unbacked supply and potentially allowing the borrowed proceeds to be kept by the attacker. This is theft of pool funds and protocol insolvency rather than merely incorrect reporting. [4](#0-3) [7](#0-6) 

### Likelihood Explanation
The attack requires no privileged call or leaked key: an unprivileged caller submits `flash_position`, supplies their own receiver, and includes repeated collateral token addresses under distinct hub markets. [8](#0-7)  The only deployment prerequisite is that the same token is listed in multiple hub markets, or that duplicate collateral legs are otherwise accepted by validation. The receiver controls the callback and only needs to make one transfer before returning. [9](#0-8) 

### Recommendation
Canonicalize `collaterals` by token `Address`, not only by `HubAssetKey`, and reject any repeated token address before taking snapshots or collecting deposits. Alternatively, atomically consume each measured receipt so it can be assigned to exactly one market; accepting multiple hub destinations for one shared token cannot be made safe while each leg independently measures the same balance delta.

Add regression coverage for:

- The same `asset` under two different `hub_id` values.
- The exact same `HubAssetKey` appearing twice.
- A collateral list whose repeated legs each specify a minimum below the single measured receipt.

### Proof of Concept
Assume markets `(hub0, X)` and `(hub1, X)` exist, and market `(hubD, D)` is flash-loanable.

```text
flash_position(
    caller = attacker,
    account_id = 0,
    spoke_id = S,
    mode = Long,
    debt = HubAssetKey { hub_id: hubD, asset: D },
    amount = A,
    receiver = attacker_receiver,
    data = arbitrary,
    collaterals = [
        (HubAssetKey { hub_id: hub0, asset: X }, 1),
        (HubAssetKey { hub_id: hub1, asset: X }, 1),
    ],
    refund_assets = [],
)
```

Execution:

1. The controller creates or loads the attacker’s account and mints/forwards `A` units of `D` to `attacker_receiver`. [4](#0-3) 
2. `snapshot_balances` stores one `X` baseline because the two collateral legs have the same token address. [1](#0-0) 
3. `execute_flash_position` on `attacker_receiver` transfers `C` units of `X` to the controller once and returns. [5](#0-4) 
4. `collect_collateral_deposits` computes `delta = C` for the first leg and pushes `(hub0:X, C)`; it then uses the same baseline and unchanged balance to compute `delta = C` for the second leg and pushes `(hub1:X, C)`. [2](#0-1) 
5. The account is credited with `2 * C` worth of collateral across the two markets despite custody increasing by only `C`, allowing `A` to be sized against the duplicated collateral and the borrowed `D` to be retained as profit.

### Citations

**File:** contracts/controller/src/payments.rs (L22-36)
```rust
/// Snapshots `holder`'s balance once per distinct asset address.
pub(crate) fn snapshot_balances(
    env: &Env,
    holder: &Address,
    assets: impl IntoIterator<Item = Address>,
) -> Map<Address, i128> {
    let mut snapshot = Map::new(env);
    for asset in assets {
        if snapshot.contains_key(asset.clone()) {
            continue;
        }
        let balance = token::Client::new(env, &asset).balance(holder);
        snapshot.set(asset, balance);
    }
    snapshot
```

**File:** contracts/controller/src/strategies/flash_position.rs (L124-130)
```rust
            // Baselines exclude funding and forwarding; count callback receipts only.
            let collateral_before = snapshot_balances(
                env,
                &controller,
                collaterals.iter().map(|(hub_asset, _)| hub_asset.asset),
            );
            let refund_before = snapshot_balances(env, &controller, refund_assets.iter());
```

**File:** contracts/controller/src/strategies/flash_position.rs (L131-141)
```rust
            invoke_receiver(
                env,
                receiver,
                caller,
                account_id,
                &debt.asset,
                amount,
                amount_received,
                &controller,
                data,
            );
```

**File:** contracts/controller/src/strategies/flash_position.rs (L271-294)
```rust
    let reported = borrow_into_controller(
        env,
        account,
        debt,
        amount,
        false,
        PositionAction::FlashPos,
        cache,
    );

    let measured = balance_delta_since(env, &debt.asset, &controller, before);
    assert_with_error!(env, measured == reported, GenericError::InternalError);
    assert_with_error!(env, measured > 0, GenericError::AmountMustBePositive);

    let forwarded = transfer_amount_measured(
        env,
        &debt.asset,
        &controller,
        receiver,
        measured,
        GenericError::AmountMustBePositive,
    );
    assert_with_error!(env, forwarded > 0, GenericError::AmountMustBePositive);
    forwarded
```

**File:** contracts/controller/src/strategies/flash_position.rs (L308-321)
```rust
    env.invoke_contract::<()>(
        receiver,
        &Symbol::new(env, "execute_flash_position"),
        (
            initiator.clone(),
            account_id,
            asset.clone(),
            amount,
            0i128,
            amount_received,
            controller.clone(),
            data.clone(),
        )
            .into_val(env),
```

**File:** contracts/controller/src/strategies/flash_position.rs (L331-344)
```rust
    let mut deposits: Vec<(HubAssetKey, i128)> = Vec::new(env);
    for (hub_asset, min_amount) in collaterals.iter() {
        let baseline = before
            .get(hub_asset.asset.clone())
            .unwrap_or_else(|| panic_with_error!(env, GenericError::InternalError));
        let delta = balance_delta_since(env, &hub_asset.asset, controller, baseline);
        assert_with_error!(
            env,
            delta >= min_amount,
            StrategyError::CollateralMinimumNotMet
        );
        if delta > 0 {
            deposits.push_back((hub_asset, delta));
        }
```

**File:** contracts/controller/src/lib.rs (L189-216)
```rust
    fn flash_position(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        mode: PositionMode,
        debt: HubAssetKey,
        amount: i128,
        receiver: Address,
        data: Bytes,
        collaterals: Vec<(HubAssetKey, i128)>,
        refund_assets: Vec<Address>,
    ) -> u64 {
        strategies::flash_position::process_flash_position(
            &env,
            &caller,
            FlashPositionParams {
                account_id,
                spoke_id,
                mode,
                debt: &debt,
                amount,
                receiver: &receiver,
                data: &data,
                collaterals: &collaterals,
                refund_assets: &refund_assets,
            },
        )
```

**File:** contracts/controller/src/strategies/mod.rs (L48-55)
```rust
pub(crate) fn strategy_finalize(
    env: &Env,
    account_id: u64,
    account: &mut Account,
    cache: &mut Context,
) {
    let _ = enforce_post_pool_solvency(env, cache, account);
    finalize_position_flow(env, account_id, account, cache, PositionSides::Both, true);
```
