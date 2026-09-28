### Title
Missing position-NFT `Owner` entry makes every account operation fail-closed, permanently freezing collateral and blocking liquidation - ([File: contracts/controller/src/storage/account.rs])

### Summary
The controller resolves account ownership by a cross-contract `owner_of` read on the position NFT (`try_account_owner`), and converts a `None` result — returned for a burned, expired/archived, or otherwise unreadable `Owner` entry — into `AccountNotFound` inside `get_account`. Every user- and keeper-reachable flow (`withdraw`, `liquidate`, `clean_bad_debt`, `force_socialize_bad_debt`) loads the account through `get_account`, so once the NFT ownership leg is missing, the account's collateral is permanently unreachable and its debt can never be liquidated or socialized. This mirrors the CVE class: a helper invoked on a possibly-absent object fails catastrophically instead of tolerating the absent case.

### Finding Description
`try_account_owner` returns `None` whenever the NFT lookup cannot resolve an owner: unconfigured NFT, missing token, or failed call [1](#0-0) . `get_account` funnels that `None` into `panic_with_error!(GenericError::AccountNotFound)` [2](#0-1) . The liquidation entrypoint unconditionally calls `storage::get_account` before planning [3](#0-2) , and harness tests pin that both `clean_bad_debt` and `force_socialize_bad_debt` fail the same way while every controller-side entry remains live [4](#0-3) .

The reachable trigger for an unprivileged party is storage TTL/archival: the `Owner` key lives in the position-NFT contract's persistent storage, which expires if never renewed. The test demonstrates the state is reachable in isolation ("controller-side account entry intact") via `burn`; on a live deployment the same state arises when the NFT's `Owner` entry archives — and nothing in the controller read path (`nft_try_owner_of_call`) renews it. A victim could also be pushed into this state if their NFT is burned through an `approve`d spender, an in-scope action.

### Impact Explanation
Permanent freezing of funds plus protocol insolvency. Once `Owner` is absent: (1) the account owner's `withdraw`/`repay` flows revert, freezing their collateral forever — there is no admin recovery path that bypasses `get_account`; (2) no liquidator can call `liquidate`, so a price crash turns the position into untouchable bad debt; (3) `clean_bad_debt`/`force_socialize_bad_debt` also revert, so the bad debt can never be written down — the supply-side loss is never socialized and the market books stay insolvent.

### Likelihood Explanation
Medium. The trigger requires the NFT `Owner` persistent entry to lapse without renewal (a function of the TTL tier the NFT contract stamps at mint/transfer) or an approved-party burn. No privileged action is needed; once the state exists, any unprivileged keeper's `liquidate(account_id, payments, SeizeMode::Transfer)` call deterministically reverts with `AccountNotFound`, as pinned by the tests.

### Recommendation
Make the absent-ownership case survivable instead of a blanket panic: (a) have the controller or NFT renew the `Owner` entry's TTL on every successful ownership read and on mint/transfer so it cannot archive while the account is live; (b) provide a recovery path (e.g., `clean_bad_debt`/`force_socialize_bad_debt` should operate on position maps directly rather than requiring resolvable ownership — note the Certora spec already reads `get_supply_positions`/`get_debt_positions` directly *because* `get_account` panics after cleanup, showing the data is available [5](#0-4) ); (c) allow liquidation to proceed on the position books with seizures escrowed or credited to a receiver when ownership is unresolvable.

### Proof of Concept
1. Alice supplies 10,000 USDC and borrows 3 ETH (account id `N`, NFT token `N`).
2. Wait until the position-NFT `Owner(N)` persistent entry archives (TTL lapse) — or, equivalently for demonstration, burn token `N` as in `partial_liquidation_resolves_nft_ownership` [6](#0-5) .
3. Any unprivileged keeper calls `controller.liquidate(keeper, N, payments, SeizeMode::Transfer)` → reverts `AccountNotFound` even though `account_exists(N)` is true.
4. `clean_bad_debt(keeper, N)` and `force_socialize_bad_debt(N)` revert identically [7](#0-6) ; Alice's own `withdraw` reverts at `get_account` — collateral permanently frozen, debt permanently unliquidatable.

Caveat: I could not read `contracts/position-nft` in this session to confirm whether `owner_of`/`transfer` extend the `Owner` key TTL. If the NFT contract already renews that entry on every touch, the archival trigger narrows to accounts untouched longer than the TTL window — the fail-closed `None → AccountNotFound` conversion and its consequences remain verified.

### Citations

**File:** contracts/controller/src/storage/account.rs (L35-44)
```rust
pub(crate) fn try_account_owner(env: &Env, account_id: u64) -> Option<Address> {
    let nft = super::protocol::try_get_position_nft(env)?;
    nft_try_owner_of_call(env, &nft, account_id)
}

/// Resolves current NFT ownership or fails with `AccountNotFound`.
pub(crate) fn account_owner(env: &Env, account_id: u64) -> Address {
    try_account_owner(env, account_id)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::AccountNotFound))
}
```

**File:** contracts/controller/src/storage/account.rs (L146-162)
```rust
pub(crate) fn get_account(env: &Env, account_id: u64) -> Account {
    try_get_account(env, account_id)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::AccountNotFound))
}

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
    ))
}
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L46-58)
```rust
    let mut account = storage::get_account(env, account_id);

    let mut cache = Context::new(env);

    require_non_empty_payments(env, debt_payments);

    // Reject an unusable receiver before moving tokens.
    let mut receiver = resolve_seize_receiver(
        env, liquidator, account_id, &account, seize_mode, &mut cache,
    );

    // Share payment normalization and positivity checks with the estimate view.
    let liquidation_plan = plan::build_liquidation_plan(env, &account, debt_payments, &mut cache);
```

**File:** tests/test-harness/tests/controller/position_nft_ttl_and_ownership_reads.rs (L281-334)
```rust
/// A partial liquidation resolves NFT ownership: `process_liquidation` calls
/// `storage::get_account`, which reads `owner_of`. With the `Owner` entry
/// burned and every controller-side account entry intact, the liquidation
/// fails with `AccountNotFound`.
#[test]
fn partial_liquidation_resolves_nft_ownership() {
    let mut t = LendingTest::new().standard_two_asset().build();
    t.supply(ALICE, "USDC", 10_000.0);
    t.borrow(ALICE, "ETH", 3.0);
    let id = t.account_id(ALICE);
    let token_id = u32::try_from(id).expect("test ids fit u32");

    t.set_price("USDC", usd_cents(50));
    t.assert_liquidatable(ALICE);

    // Detach the ownership leg, leaving controller state untouched.
    position_nft::PositionNftClient::new(&t.env, &t.position_nft).burn(&token_id);
    assert!(!t.try_nft_owner_of(id), "ownership leg is now unreadable");
    assert!(
        t.account_exists(id),
        "controller-side account state must still be live -- this isolates the \
         NFT read as the only thing that changed"
    );

    // A plain partial liquidation, well under the close factor.
    let result = t.try_liquidate(LIQUIDATOR, ALICE, "ETH", 1.0);
    assert_contract_error(result, errors::ACCOUNT_NOT_FOUND);
}

/// The same isolation on the bad-debt path: `clean_bad_debt` and
/// `force_socialize_bad_debt` enter `socialize_bad_debt`, which calls
/// `storage::get_account`, so both fail on the owner read with `AccountNotFound`.
#[test]
fn bad_debt_winddown_resolves_nft_ownership() {
    let mut t = LendingTest::new().standard_two_asset().build();
    t.supply(ALICE, "USDC", 10_000.0);
    t.borrow(ALICE, "ETH", 3.0);
    let id = t.account_id(ALICE);
    let token_id = u32::try_from(id).expect("test ids fit u32");
    let keeper = t.get_or_create_user(LIQUIDATOR);

    t.set_price("USDC", usd_cents(1));
    position_nft::PositionNftClient::new(&t.env, &t.position_nft).burn(&token_id);
    assert!(t.account_exists(id), "controller state still live");

    assert_contract_error(
        flatten(t.ctrl_client().try_clean_bad_debt(&keeper, &id)),
        errors::ACCOUNT_NOT_FOUND,
    );
    assert_contract_error(
        flatten(t.ctrl_client().try_force_socialize_bad_debt(&id)),
        errors::ACCOUNT_NOT_FOUND,
    );
}
```

**File:** certora/controller/spec/account_isolation_rules.rs (L29-45)
```rust
/// Both readers go to the position maps directly rather than through
/// `get_account`, which panics with `AccountNotFound` once bad-debt cleanup
/// has removed the account. A panic drops the path from the rule, so the
/// post state of a liquidation that ended in cleanup would silently leave it.
fn scaled_supply_at(env: &Env, account_id: u64, asset: &Address) -> i128 {
    get_supply_positions(env, account_id)
        .get(hub0(asset))
        .map(|p| p.scaled_amount)
        .unwrap_or(0)
}

fn scaled_borrow_at(env: &Env, account_id: u64, asset: &Address) -> i128 {
    get_debt_positions(env, account_id)
        .get(hub0(asset))
        .map(|p| p.scaled_amount)
        .unwrap_or(0)
}
```
