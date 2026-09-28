### Title
Stale delegate grants silently reactivate when a position NFT returns to its granting owner - (File: contracts/controller/src/storage/account.rs)

### Summary

Delegate authorization is keyed only by `account_id` and the address stored in `DelegateGrant.granted_by`; changing NFT ownership merely makes the grant dormant rather than deleting it. When the account NFT is transferred back to the original owner, the old delegate list becomes active again without a new grant or owner authorization. A previously delegated active manager can then act as owner-equivalent and withdraw collateral or borrow assets to an arbitrary recipient.

### Finding Description

`get_delegates` treats a grant as live whenever `grant.granted_by` equals the account’s current NFT owner, while ownership itself is resolved dynamically through `owner_of(account_id)` [1](#0-0) [2](#0-1) . If a different owner calls `remove_delegate`, the stale grant is deleted only when that new owner performs the revocation; an NFT transfer itself performs no controller-side delegate cleanup [3](#0-2) . Once the NFT returns to `granted_by`, `is_owner_or_delegate` again accepts every delegated address that remains an active position manager [4](#0-3) . The withdrawal and borrow paths then use that same owner-or-delegate check and permit `to` to select an external recipient [5](#0-4) [6](#0-5) .

### Impact Explanation

This is theft of user funds and unauthorized debt creation. After the stale grant reactivates, the manager can call `withdraw(caller=manager, account_id, withdrawals, to=Some(manager))`, where amount `0` requests the full position, and can call `borrow(..., to=Some(manager))` against the restored owner’s collateral [7](#0-6) . Neither operation requires the restored owner to reauthorize the delegate because authorization is inferred solely from the persistent `DelegateGrant.granted_by` field [2](#0-1) [8](#0-7) .

### Likelihood Explanation

The sequence uses only normal account delegation and position-NFT transfers: the original owner delegates an active manager, the NFT moves to another owner, and it later returns to the original owner. Position NFT ownership is intentionally transferable and independently stored from controller delegates, so this lifecycle is reachable without changing controller configuration [9](#0-8) [10](#0-9) . Likelihood depends on an account round-tripping to the granting owner and the delegate remaining an active manager, but the reactivation requires no additional victim signature.

### Recommendation

Invalidate `ControllerKey::Delegates(account_id)` whenever beneficial ownership changes. Because the generic NFT transfer path cannot notify the controller, the controller should bind grants to an ownership epoch or nonce stored with account metadata, increment that epoch on first use after an ownership change, or route transfers through a controller-aware wrapper that clears delegates. At minimum, delete the delegate entry whenever `try_account_owner` resolves to an address different from `DelegateGrant.granted_by`, including during account reads, rather than waiting for a privileged or later manual revocation [2](#0-1) .

### Proof of Concept

1. `alice` creates and funds account `A`, then calls `add_delegate(alice, A, manager)`, which stores `DelegateGrant { granted_by: alice, delegates: [manager] }` [11](#0-10) .
2. `alice` transfers position NFT `A` to `bob`; controller ownership is thereafter resolved from `owner_of(A)`, so the grant is dormant because `granted_by != bob` [1](#0-0) [12](#0-11) .
3. `bob` transfers NFT `A` back to `alice`; no transfer path removes `ControllerKey::Delegates(A)` [13](#0-12) .
4. `manager` calls `borrow(manager, A, [(debt_hub_asset, amount)], Some(manager))`; `is_owner_or_delegate` resolves the owner as `alice`, finds the old grant, and authorizes the borrow [4](#0-3) [6](#0-5) .
5. Alternatively, `manager` calls `withdraw(manager, A, [(collateral_hub_asset, 0)], Some(manager))`; the zero amount is treated as withdraw-all and pays the supplied recipient [14](#0-13) [15](#0-14) .

### Citations

**File:** contracts/controller/src/storage/account.rs (L33-44)
```rust
/// Resolves current NFT ownership; returns `None` for an unconfigured NFT,
/// unmintable ID, missing token, or failed lookup. Ownership fails closed.
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

**File:** contracts/controller/src/storage/account.rs (L174-181)
```rust
/// Returns grants stamped by `owner`, or an empty list. Ownership changes
/// invalidate a previous owner's grants without deleting them.
pub(crate) fn get_delegates(env: &Env, account_id: u64, owner: &Address) -> Vec<Address> {
    get_user::<DelegateGrant>(env, &ControllerKey::Delegates(account_id))
        .filter(|grant| grant.granted_by == *owner)
        .map(|grant| grant.delegates)
        .unwrap_or_else(|| Vec::new(env))
}
```

**File:** contracts/controller/src/storage/account.rs (L223-247)
```rust
/// Removes a live delegate and reports whether it changed the list.
/// Deletes stale grants but returns false, preventing those grants from
/// reactivating if the NFT returns to their original owner.
pub(crate) fn remove_delegate(
    env: &Env,
    account_id: u64,
    owner: &Address,
    delegate: &Address,
) -> bool {
    let key = ControllerKey::Delegates(account_id);
    let Some(grant) = get_user::<DelegateGrant>(env, &key) else {
        return false;
    };
    if grant.granted_by != *owner {
        env.storage().persistent().remove(&key);
        return false;
    }
    let mut delegates = grant.delegates;
    let Some(index) = delegates.first_index_of(delegate) else {
        return false;
    };
    delegates.remove(index);
    set_delegates(env, account_id, owner, &delegates);
    true
}
```

**File:** contracts/controller/src/storage/account.rs (L249-256)
```rust
/// Deletes metadata, both position maps, and delegates. Does not burn the NFT.
pub(crate) fn remove_account_entry(env: &Env, account_id: u64) {
    let persistent = env.storage().persistent();
    persistent.remove(&ControllerKey::AccountMeta(account_id));
    persistent.remove(&ControllerKey::SupplyPositions(account_id));
    persistent.remove(&ControllerKey::BorrowPositions(account_id));
    persistent.remove(&ControllerKey::Delegates(account_id));
}
```

**File:** contracts/controller/src/account.rs (L114-139)
```rust
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
```

**File:** contracts/controller/src/account.rs (L228-263)
```rust
/// Requires the NFT owner to grant an active manager access; renews instance TTL.
pub(crate) fn add_delegate(env: &Env, caller: Address, account_id: u64, delegate: Address) {
    storage::renew_controller_instance(env);
    set_account_delegate(env, &caller, account_id, &delegate, true);
}

/// Requires the NFT owner to revoke manager access; renews instance TTL.
pub(crate) fn remove_delegate(env: &Env, caller: Address, account_id: u64, delegate: Address) {
    storage::renew_controller_instance(env);
    set_account_delegate(env, &caller, account_id, &delegate, false);
}

/// Authenticates the NFT owner and updates delegates; grants require an active
/// manager. Emits an event only when the current owner's delegate list changes.
fn set_account_delegate(
    env: &Env,
    caller: &Address,
    account_id: u64,
    delegate: &Address,
    add: bool,
) {
    caller.require_auth();
    require_account_owner(env, account_id, caller);
    if add {
        // Reject dormant grants that could gain authority on later manager activation.
        assert_with_error!(
            env,
            storage::get_position_manager(env, delegate).is_some_and(|c| c.is_active),
            GenericError::NotAuthorized
        );
    }

    let changed = if add {
        storage::add_delegate(env, account_id, caller, delegate)
    } else {
        storage::remove_delegate(env, account_id, caller, delegate)
```

**File:** contracts/controller/src/positions/supply.rs (L147-158)
```rust
    validation::require_authorized_caller(env, caller);

    let mut account = storage::get_account(env, account_id);
    require_owner_or_delegate(env, account_id, caller, &account.owner);

    let recipient = to.unwrap_or_else(|| caller.clone());
    let mut cache = Context::new(env);
    require_external_recipient(env, &mut cache, &recipient);
    let aggregated = payments::aggregate_payments(env, withdrawals, payments::ZeroLeg::MeansAll);

    let paid = settle_withdraw(env, &mut account, &recipient, &aggregated, &mut cache);
    let _ = enforce_post_pool_solvency(env, &mut cache, &mut account);
```

**File:** contracts/controller/src/positions/supply.rs (L181-199)
```rust
    for (hub_asset, amount) in aggregated.iter() {
        enforce_spoke_asset_flags(
            env,
            cache,
            account.spoke_id,
            &hub_asset,
            FreezePolicy::AllowOnExit,
        );
        let position = get_supply_position_or_panic(env, account, &hub_asset);
        let requested = if amount == 0 {
            WITHDRAW_ALL_SENTINEL
        } else {
            amount
        };
        entries.push_back(PoolWithdrawEntry {
            action: make_pool_action(&position, requested, hub_asset.clone()),
            protocol_fee: 0,
        });
    }
```

**File:** contracts/controller/src/positions/debt.rs (L40-58)
```rust
    validation::require_authorized_caller(env, caller);

    let mut account = storage::get_account(env, account_id);
    require_owner_or_delegate(env, account_id, caller, &account.owner);

    let recipient = to.unwrap_or_else(|| caller.clone());
    let mut cache = Context::new(env);
    require_external_recipient(env, &mut cache, &recipient);
    let aggregated = payments::aggregate_positive_payments(env, borrows);

    validate_position_entry_gates(
        env,
        &account,
        &aggregated,
        &mut cache,
        AccountPositionType::Borrow,
    );
    settle_borrow(env, &mut account, &recipient, &aggregated, &mut cache);

```

**File:** contracts/controller/src/lib.rs (L104-128)
```rust
    /// Borrows against `account_id`'s collateral, paying `to` or the caller.
    /// Requires owner or delegate authorization and post-borrow solvency.
    #[when_not_paused]
    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) {
        positions::process_borrow(&env, &caller, account_id, &borrows, to);
    }

    /// Withdraws collateral to `to` or the caller and returns actual amounts in
    /// asset units. Zero withdraws an asset's full position. Requires owner or
    /// delegate authorization and post-withdrawal solvency.
    fn withdraw(
        env: Env,
        caller: Address,
        account_id: u64,
        withdrawals: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) -> Vec<(HubAssetKey, i128)> {
        positions::process_withdraw(&env, &caller, account_id, &withdrawals, to)
    }
```

**File:** contracts/position-nft/src/contract.rs (L1-5)
```rust
//! Lending-position NFT: one token per controller account, and the token id is
//! the account id. The token owner (`owner_of`) is the account owner.
//! Mint, burn and upgrade are controller-only; `renew` is permissionless. The
//! rest is the stock OpenZeppelin non-fungible interface with a custom
//! `token_uri`.
```

**File:** common/src/types/controller.rs (L63-73)
```rust
/// A delegate list stamped with the owner who granted it. The grant is live only while
/// `granted_by` owns the account's NFT: after an NFT transfer, `get_delegates` reads it as
/// empty for the new owner. The new owner's next `add_delegate` or `remove_delegate`
/// overwrites or deletes the stale entry. If the NFT returns to `granted_by` before such a
/// write, the original delegate list is live again.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegateGrant {
    pub granted_by: Address,
    pub delegates: Vec<Address>,
}
```
