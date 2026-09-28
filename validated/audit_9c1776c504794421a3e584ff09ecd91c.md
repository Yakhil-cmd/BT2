### Title
Stale cached owner in `Account` allows former owner/delegates to act on a transferred position - ([File: contracts/controller/src/account.rs](contracts/controller/src/account.rs))

### Summary
`Account` stores `owner` as a snapshot taken at mint time, and the privileged-operation gate `require_owner_or_delegate`/`is_owner_or_delegate` compares `caller` against that stored snapshot rather than the live position-NFT owner. After a position NFT transfer, the previous owner (and any delegate granted by the previous owner) can still call `borrow`, `withdraw`, `multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `flash_position`, and `migrate_from_blend` on the account — stealing the new owner's collateral. The DN-injection analog: an identity asserted in one layer (the stored `owner` string/field) is trusted in another (the auth gate) without re-deriving it from the authoritative source (live NFT `owner_of`).

### Finding Description
`create_account_with` mints the NFT to `owner` and persists `Account { owner: owner.clone(), .. }` plus `AccountMeta { spoke_id, mode }` — the owner is a stored field, not derived [1](#0-0) . All position-mutating flows load the account and authorize via `require_owner_or_delegate(env, account_id, caller, &account.owner)`, which short-circuits on `caller == owner` where `owner` is the stale snapshot [2](#0-1) . Contrast with `require_account_owner`, which correctly queries `storage::account_owner` (the live NFT `owner_of`) — this proves the codebase itself distinguishes cached vs. live ownership [3](#0-2) . No code path observed rewrites `account.owner` or the per-owner delegate list after an NFT `transfer`/`approve`-triggered ownership change, so delegates granted under the old owner also remain effective: `get_delegates(env, account_id, owner)` is keyed by the stored `owner` [4](#0-3) .

### Impact Explanation
An attacker sells/transfers a funded position NFT to a victim (or transfers it after accumulating collateral), then calls `withdraw(account_id, all collateral, to: attacker)` or `borrow` max debt `to` themselves. `process_withdraw`/`process_borrow` authorize via `require_owner_or_delegate` against `account.owner` — still the attacker — and release pool funds `to` the attacker. Theft of the full collateral value of any transferred account; also enables leaving the buyer with unexpected debt.

### Likelihood Explanation
Single unprivileged transaction: `position-nft.transfer(victim_or_counterparty, token_id)` then `controller.withdraw`. Requires the victim to acquire the NFT expecting its collateral — the exact intended use of the position NFT as transferable account ownership, per the SDK docs noting "a position-NFT transfer transfers control of the whole lending account". No privilege, oracle manipulation, or timing needed.

### Recommendation
On every privileged entrypoint, resolve the owner from `storage::account_owner` (live NFT `owner_of`) instead of the stored `Account.owner` field, or resync `account.owner` and clear the old owner's delegate map whenever ownership changes. At minimum, gate `require_owner_or_delegate` on `account_owner(env, account_id)` and key delegate lookups by the live owner.

### Proof of Concept
```rust
// env: controller + NFT deployed, attacker owns account_id with collateral
let attacker = Address::generate(&env);
let victim = Address::generate(&env);
let account_id = ctrl.supply(&attacker, &0, &spoke_id, &collateral_vec);

// Sell/transfer the NFT
nft.transfer(&attacker, &victim, &account_id);

// Live owner is now victim...
assert_eq!(nft.owner_of(&account_id), victim);

// ...but cached Account.owner is still attacker; withdraw succeeds and
// pays the attacker the victim's collateral:
ctrl.withdraw(&attacker, &account_id, &all_collateral, &Some(attacker.clone()));
// borrows also succeed against the victim's remaining collateral
ctrl.borrow(&attacker, &account_id, &debt_vec, &Some(attacker));
```
Root cause: `is_owner_or_delegate` line 121 `caller == owner` uses `account.owner` (snapshot) while `require_account_owner` line 146 uses live `account_owner` — inconsistent identity sources across auth gates [5](#0-4) .

**Caveat:** index coverage may omit a resync path (e.g., an NFT-transfer hook or `get_account` rewriting `owner`). If `Account.owner` is refreshed from the NFT on every load, this finding is void; the code surface reviewed shows no such refresh in `get_account`'s callers and the deliberate distinction between `account.owner` and `account_owner()` suggests it is not.

### Citations

**File:** contracts/controller/src/account.rs (L63-71)
```rust
    let account_id = nft_mint_call(env, &nft, owner);
    let account = Account {
        owner: owner.clone(),
        spoke_id,
        mode,
        supply_positions: Map::new(env),
        borrow_positions: Map::new(env),
    };
    storage::set_account_meta(env, account_id, &AccountMeta { spoke_id, mode });
```

**File:** contracts/controller/src/account.rs (L98-147)
```rust
    let account = storage::get_account(env, account_id);
    match guard {
        AccountGuard::Supply => require_spoke_match(env, &account, spoke_id),
        AccountGuard::Migrate => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
        }
        AccountGuard::Multiply => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
            assert_with_error!(env, account.mode == mode, GenericError::AccountModeMismatch);
        }
    }
    (account_id, account)
}

/// Accepts the owner or a registered, active manager delegated by that owner.
pub(crate) fn is_owner_or_delegate(
    env: &Env,
    account_id: u64,
    caller: &Address,
    owner: &Address,
) -> bool {
    if caller == owner {
        return true;
    }
    let active_manager =
        storage::get_position_manager(env, caller).is_some_and(|config| config.is_active);
    active_manager && storage::get_delegates(env, account_id, owner).contains(caller)
}

/// Requires the owner or a registered, active manager delegated by that owner.
pub(crate) fn require_owner_or_delegate(
    env: &Env,
    account_id: u64,
    caller: &Address,
    owner: &Address,
) {
    if is_owner_or_delegate(env, account_id, caller, owner) {
        return;
    }
    panic_with_error!(env, GenericError::NotAuthorized);
}

/// Returns metadata after verifying that `caller` currently owns the account NFT.
pub(crate) fn require_account_owner(env: &Env, account_id: u64, caller: &Address) -> AccountMeta {
    let meta = storage::get_account_meta(env, account_id);
    let owner = storage::account_owner(env, account_id);
    assert_with_error!(env, owner == *caller, GenericError::AccountNotInMarket);
    meta
```
