### Title
Archived collateral positions are treated as empty, allowing permissionless bad-debt cleanup to erase a collateralized account - (File: contracts/controller/src/storage/account.rs)

### Summary
The controller stores an account’s supply positions and borrow positions in separate persistent entries, but reads a missing or archived `SupplyPositions` entry as an empty map instead of distinguishing it from a truly collateral-free account. [1](#0-0)  An attacker can keep the account metadata, debt positions, and NFT ownership reachable through permissionless `repay` calls while the `SupplyPositions` entry remains unrenewed, then call `clean_bad_debt` after that entry archives. [2](#0-1) [3](#0-2)  `clean_bad_debt` then values the account as having nonzero debt and zero collateral, socializes the debt, deletes the account state, and burns the position NFT, permanently destroying the user’s claim to the archived collateral. [4](#0-3) [5](#0-4) 

### Finding Description
Persistent reads renew only the specific user key that was read, so repeated debt-only accesses can keep `AccountMeta`, `BorrowPositions`, and NFT ownership alive without renewing `SupplyPositions`. [6](#0-5)  The repayment path intentionally loads metadata, current owner, and debt while leaving supply deliberately unloaded, so a permissionless repayment can refresh every prerequisite for `get_account` except the collateral map. [7](#0-6)  `get_account` then combines the live metadata and owner with `get_supply_positions`, which returns an empty map for an absent entry rather than reporting that the collateral record is unavailable. [8](#0-7) [9](#0-8)  `clean_bad_debt` requires only open debt and `total_debt > total_collateral` with collateral at or below the dust threshold, so the artificially empty supply map satisfies both conditions for any positive debt. [10](#0-9)  Cleanup only iterates the loaded supply and debt maps, so it writes down the debt but never seizes or preserves the missing supply position before deleting the account and burning its NFT. [5](#0-4) 

### Impact Explanation
A borrower’s collateral claim can be permanently lost even though the account still has valid collateral recorded only in an archived controller entry. [1](#0-0) [5](#0-4)  Once `remove_account_and_burn_nft` deletes the metadata and burns the position NFT, later restoring the archived `SupplyPositions` entry does not recover a usable account. [11](#0-10)  This is a permanent freezing of user funds and a forced debt write-down reachable by any unprivileged address that can submit `repay` and `clean_bad_debt`. [3](#0-2) [12](#0-11) 

### Likelihood Explanation
The attack does not require privileged calls, leaked keys, oracle manipulation, or control of the victim account because `repay` and `clean_bad_debt` are both callable by third parties. [12](#0-11)  The main precondition is that the victim’s `SupplyPositions` entry must archive while its sibling account entries remain available, which can be induced by using minimal `repay` calls to renew the debt-side account entries without touching the supply map. [6](#0-5) [7](#0-6)  The attacker must leave at least one nonzero debt position and may need to donate small repayments to keep the required entries live, so likelihood depends on account inactivity and whether off-chain TTL maintenance misses the collateral entry. [10](#0-9) [13](#0-12) 

### Recommendation
Do not use an empty map as proof that an account has no collateral when its `SupplyPositions` entry is missing. [1](#0-0)  Persist an account-level supply/debt presence marker or position count in `AccountMeta`, update it whenever positions change, and make `clean_bad_debt` fail closed when metadata indicates collateral exists but the corresponding position entry is unavailable. [14](#0-13) [4](#0-3)  Equivalently, keep collateral and debt records under a storage layout whose availability is atomic for destructive cleanup, or require successful restoration of all expected position entries before admission to bad-debt socialization. [5](#0-4) 

### Proof of Concept
1. A victim creates an account, supplies collateral, and keeps a positive debt position. [15](#0-14) 
2. An attacker periodically calls `repay(caller=attacker, account_id=victim_id, payments=[(debt_hub_asset, minimal_positive_amount)])`, choosing an amount large enough to burn nonzero debt shares but leaving debt outstanding; this path renews the metadata, owner lookup, and debt-side storage without reading or renewing `SupplyPositions`. [7](#0-6) [6](#0-5) 
3. Once the victim’s `SupplyPositions` entry archives while `AccountMeta`, `BorrowPositions`, and NFT ownership remain live, the attacker calls `clean_bad_debt(caller=attacker, account_id=victim_id)`. [16](#0-15) 
4. The controller reads the missing supply entry as an empty map, calculates `total_collateral = 0` and `total_debt > 0`, and passes the dust-capped bad-debt gate. [1](#0-0) [17](#0-16) 
5. `execute_bad_debt_cleanup` iterates only the loaded borrow positions, socializes that debt, deletes the account entries, and burns the position NFT while the victim’s supply position is never processed. [5](#0-4)

### Citations

**File:** contracts/controller/src/storage/account.rs (L46-60)
```rust
/// Returns stored account metadata, or `None` when absent.
pub(crate) fn try_get_account_meta(env: &Env, account_id: u64) -> Option<AccountMeta> {
    get_user(env, &ControllerKey::AccountMeta(account_id))
}

/// Returns account metadata or fails with `AccountNotInMarket`.
pub(crate) fn get_account_meta(env: &Env, account_id: u64) -> AccountMeta {
    try_get_account_meta(env, account_id)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::AccountNotInMarket))
}

/// Stores account metadata and renews user TTL.
pub(crate) fn set_account_meta(env: &Env, account_id: u64, meta: &AccountMeta) {
    set_user(env, &ControllerKey::AccountMeta(account_id), meta);
}
```

**File:** contracts/controller/src/storage/account.rs (L63-72)
```rust
pub(crate) fn get_supply_positions(
    env: &Env,
    account_id: u64,
) -> Map<HubAssetKey, AccountPositionRaw> {
    get_user(env, &ControllerKey::SupplyPositions(account_id)).unwrap_or_else(|| Map::new(env))
}

/// Returns raw debt positions, defaulting to an empty map.
pub(crate) fn get_debt_positions(env: &Env, account_id: u64) -> Map<HubAssetKey, DebtPositionRaw> {
    get_user(env, &ControllerKey::BorrowPositions(account_id)).unwrap_or_else(|| Map::new(env))
```

**File:** contracts/controller/src/storage/account.rs (L151-160)
```rust
/// Loads both position maps and current NFT ownership; returns `None` when
/// metadata is absent or ownership cannot be resolved.
pub(crate) fn try_get_account(env: &Env, account_id: u64) -> Option<Account> {
    let meta = try_get_account_meta(env, account_id)?;
    let owner = try_account_owner(env, account_id)?;
    Some(account_from_parts(
        owner,
        meta,
        get_supply_positions(env, account_id),
        get_debt_positions(env, account_id),
```

**File:** contracts/controller/src/storage/account.rs (L164-171)
```rust
/// Loads metadata, current owner, and debt; leaves supply deliberately unloaded.
/// Missing metadata raises `AccountNotInMarket`; unresolved ownership raises
/// `AccountNotFound`. The empty supply map does not prove supply is absent.
pub(crate) fn get_account_borrow_only(env: &Env, account_id: u64) -> Account {
    let meta = get_account_meta(env, account_id);
    let owner = account_owner(env, account_id);
    let borrow_positions = get_debt_positions(env, account_id);
    account_from_parts(owner, meta, Map::new(env), borrow_positions)
```

**File:** docs/reference/endpoints.md (L24-29)
```markdown
| `supply(caller: Address, account_id: u64, spoke_id: u32, assets: Vec<(HubAssetKey, i128)>) -> u64` | Existing assets only for third parties | gated | Supply measured deposits; id 0 creates Normal account. |
| `borrow(caller: Address, account_id: u64, borrows: Vec<(HubAssetKey, i128)>, to: Option<Address>)` | NFT owner/delegate | gated | Debt booked to account; recipient defaults to caller. |
| `withdraw(caller: Address, account_id: u64, withdrawals: Vec<(HubAssetKey, i128)>, to: Option<Address>) -> Vec<(HubAssetKey, i128)>` | NFT owner/delegate | open | Zero means full withdrawal; returns the amounts paid. |
| `repay(caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>)` | None | open | Anyone can repay; excess returns to caller. |
| `liquidate(liquidator: Address, account_id: u64, debt_payments: Vec<(HubAssetKey, i128)>, seize_mode: SeizeMode) -> u64` | None; credit receiver owner/delegate | open | Pro-rata seizure; Transfer returns 0, Credit returns receiver id. |
| `clean_bad_debt(caller: Address, account_id: u64)` | None | open | Debt exceeds collateral and collateral <= $5; socialize and burn NFT. |
```

**File:** docs/reference/endpoints.md (L53-55)
```markdown
### Risk checks and pause flags

After pool accounting, `borrow`, `withdraw` and the six account strategies require LTV-weighted collateral to cover debt and health factor (HF) to be at least 1. If debt remains, LTV-weighted collateral must also meet the minimum-borrow floor. Ordinary `supply` and `repay` skip these checks; repayment loads debt positions only. Liquidation uses separate admission and sizing rules. See [formulas](formulas.md) for the calculations.
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-214)
```rust
/// Authorizes permissionless dust-gated cleanup outside flash loans.
pub(crate) fn process_clean_bad_debt(env: &Env, caller: &Address, account_id: u64) {
    caller.require_auth();
    validation::require_not_flash_loaning(env);
    clean_bad_debt_standalone(env, account_id);
}

/// Admission condition for bad-debt socialization.
#[derive(Clone, Copy, PartialEq)]
enum BadDebtGate {
    /// Permissionless: insolvent *and* collateral at or below the dust threshold.
    DustCapped,
    /// Owner-only: insolvent alone, with no cap on the collateral left behind.
    InsolventOnly,
}

/// Requires open debt and the selected insolvency gate, then cleans up the account.
fn socialize_bad_debt(env: &Env, account_id: u64, gate: BadDebtGate) {
    let mut cache = Context::new(env);
    let account = storage::get_account(env, account_id);
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L216-237)
```rust
    assert_with_error!(
        env,
        !account.borrow_positions.is_empty(),
        CollateralError::DebtPositionNotFound
    );

    let totals = risk::calculate_account_risk_totals(
        env,
        &mut cache,
        &account.supply_positions,
        &account.borrow_positions,
    );

    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);

    bad_debt::execute_bad_debt_cleanup(env, &mut cache, account_id, &account, &totals);
```

**File:** contracts/controller/src/positions/liquidation/bad_debt.rs (L21-60)
```rust
    let mut entries: Vec<PoolSeizeEntry> = Vec::new(env);
    for (hub_asset, position) in iter_typed_positions(&account.supply_positions) {
        cache.apply_spoke_exit(
            account.spoke_id,
            UsageSide::Supply,
            &hub_asset,
            position.scaled_amount,
        );
        entries.push_back(PoolSeizeEntry {
            hub_asset,
            side: AccountPositionType::Deposit,
            position: (&position).into(),
        });
    }
    for (hub_asset, position) in iter_debt_positions(&account.borrow_positions) {
        cache.apply_spoke_exit(
            account.spoke_id,
            UsageSide::Borrow,
            &hub_asset,
            position.scaled_amount,
        );
        entries.push_back(PoolSeizeEntry {
            hub_asset,
            side: AccountPositionType::Borrow,
            position: (&position).into(),
        });
    }
    let pool_addr = cache.cached_pool_address();
    pool_seize_positions_call(env, &pool_addr, &entries);

    cache.persist_spoke_usage();

    CleanBadDebtEvent {
        account_id,
        total_borrow_usd_wad: totals.total_debt.raw(),
        total_collateral_usd_wad: totals.total_collateral.raw(),
    }
    .publish(env);

    remove_account_and_burn_nft(env, account_id);
```

**File:** contracts/controller/src/storage/protocol.rs (L189-195)
```rust
/// Reads a persistent value and renews user TTL only when present.
pub(super) fn get_user<V: TryFromVal<Env, Val>>(env: &Env, key: &ControllerKey) -> Option<V> {
    let value: Option<V> = env.storage().persistent().get(key);
    if value.is_some() {
        renew_persistent_key(env, key, TTL_THRESHOLD_USER, TTL_BUMP_USER);
    }
    value
```

**File:** services/keeper/README.md (L139-154)
```markdown
| Controller instance | instance | configured controller | yes |
| Price-aggregator `Oracle(PriceKey)`: token and `Ref` rows | persistent | the aggregator's own `OracleKeys` index, falling back to configured markets | yes |
| Controller `Hub(id)` / `Spoke(id)` | persistent | `LastHubId` / `LastSpokeId` | yes |
| Account state (`AccountMeta` / `SupplyPositions` / `BorrowPositions` / `Delegates`) | persistent | position-NFT counter scan | yes |
| Account ownership (`Owner(token_id)` on the position NFT) | persistent | position-NFT counter scan | yes, in the `per_user` metrics group. OpenZeppelin extends it to 30 days and the controller extends account keys to 120 days, so it archives first if unrenewed |
| Controller access-control keys | persistent | `ExistingRoles` | yes, when present |
| Controller `SpokeAsset` / `SpokeUsage` / `SpokeFlagsEpoch` | persistent | `1..=LastSpokeId` × configured markets | yes, in the `hub_spoke` metrics group |
| Controller `BlendPoolAllowed` / `PositionManager` | persistent | `contracts.blend_pools` / `contracts.position_managers` | yes, when listed, in the `hub_spoke` metrics group |
| Pool `Params/State(HubAssetKey)` | persistent | configured markets | yes |
| Governance instance | instance | configured governance | yes |
| Governance role keys | persistent | `ExistingRoles` | yes, when configured |
| Pool / position-NFT / receiver / price-aggregator instances and WASM code | instance / code | instance reads | yes |
| XOXNO oracle adapter instance, WASM and persistent keys | instance / code / persistent | configured `xoxno_oracle_adapter` | yes, when configured |
| Third-party instances the protocol reads through (`contracts.extra_instances`: RedStone adapter, swap router) and their WASM code | instance / code | configured list | yes, when configured — nothing in the protocol writes these, so nothing else renews them |
| Timelock `OperationLedger(BytesN<32>)` | persistent | event-only | no, documented gap |
| Temporary keys | temporary | n/a | no, expire by design |
```
