### Title
Stale delegate grants regain authority after position-NFT ownership returns - (File: contracts/controller/src/storage/account.rs)

### Summary

Delegate grants are stamped only with the granting owner’s address, not an ownership epoch or generation, so a grant becomes inactive after an NFT transfer but is not deleted. [1](#0-0)  If the NFT later returns to the original owner before an intervening owner overwrites or removes the grant, the old delegate list becomes active again. [2](#0-1)  A malicious or compromised position manager can then use the revived grant to borrow assets to itself while leaving the debt on the victim’s account. [3](#0-2) [4](#0-3) 

### Finding Description

`ControllerKey::Delegates(account_id)` stores one `DelegateGrant` containing `granted_by` and the delegate list. [5](#0-4)  `get_delegates` returns the stored list only when `grant.granted_by` equals the current NFT owner; otherwise it reports an empty list but leaves the entry intact. [2](#0-1) 

Because ownership is read dynamically from the position NFT, transferring the account NFT makes an old owner’s grant inactive without clearing it. [6](#0-5)  When the NFT returns to the original `granted_by` address, `get_delegates` once again returns the old list because there is no transfer counter or epoch distinguishing the new ownership period from the old one. [2](#0-1) 

The stale entry is removed only if an intervening owner calls `add_delegate` or `remove_delegate`; otherwise it survives indefinitely. [7](#0-6) [8](#0-7)  Authorization then accepts any globally active position manager whose address appears in that revived list. [9](#0-8) 

`borrow` explicitly permits an authorized owner or delegate to choose an arbitrary external recipient through `to`. [10](#0-9)  The pool pays the borrowed amount to that recipient while the resulting debt mutation is merged into the victim’s account. [11](#0-10) 

### Impact Explanation

This can cause theft of user funds and protocol insolvency risk: the revived manager can take the maximum permitted borrow to its own address, while the victim retains the debt and risks liquidation of the collateral backing it. [12](#0-11) [11](#0-10)  The delegate can also invoke other owner-or-delegate account actions, subject to the same authorization check and position gates. [13](#0-12) 

### Likelihood Explanation

The attack requires the victim to have delegated to a globally active manager, the NFT to move to another owner and later return to the original owner, and the intervening owner not to call `add_delegate` or `remove_delegate`. [14](#0-13) [15](#0-14)  Those conditions are plausible during marketplace transfers, custody changes, failed sales, or round-trip use of a position NFT, and the stale manager only needs to monitor ownership and submit the final privileged call. [6](#0-5) 

### Recommendation

Invalidate delegate grants permanently on every NFT ownership change rather than merely filtering them by owner address. Prefer storing an ownership generation or transfer epoch in the grant and incrementing that epoch through a controller callable NFT transfer hook, or have the NFT directly clear `Delegates(account_id)` on transfer. As a defense-in-depth measure, also document and provide an explicit account-transfer preparation path that calls `remove_delegate` before ownership changes.

### Proof of Concept

Preconditions: Alice owns account `id`, `M` is an active registered position manager, and Alice has called `add_delegate(id, M)`. The account has sufficient collateral for `amount` and the selected debt market is borrowable.

```text
1. Alice transfers the position NFT to Bob:
   position_nft.transfer(from=alice, to=bob, token_id=id)

2. Bob does not call add_delegate or remove_delegate.
   The Alice-stamped grant is inactive but remains stored.

3. Bob transfers the NFT back to Alice:
   position_nft.transfer(from=bob, to=alice, token_id=id)

4. M submits:
   controller.borrow(
       caller=M,
       account_id=id,
       borrows=[(HubAssetKey { hub_id, asset: debt_asset }, amount)],
       to=Some(M)
   )
```

After step 3, `account_owner(id)` is Alice again, so `get_delegates(id, Alice)` returns the stale list containing `M`. [2](#0-1)  `is_owner_or_delegate` accepts `M` because its manager registration is active and the revived list contains `M`. [9](#0-8)  The controller then instructs the pool to pay the borrow to `M` and records the debt on Alice’s account. [11](#0-10)

### Citations

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

**File:** contracts/controller/src/storage/account.rs (L33-43)
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
```

**File:** contracts/controller/src/storage/account.rs (L174-180)
```rust
/// Returns grants stamped by `owner`, or an empty list. Ownership changes
/// invalidate a previous owner's grants without deleting them.
pub(crate) fn get_delegates(env: &Env, account_id: u64, owner: &Address) -> Vec<Address> {
    get_user::<DelegateGrant>(env, &ControllerKey::Delegates(account_id))
        .filter(|grant| grant.granted_by == *owner)
        .map(|grant| grant.delegates)
        .unwrap_or_else(|| Vec::new(env))
```

**File:** contracts/controller/src/storage/account.rs (L201-220)
```rust
/// Adds a delegate, enforcing `MAX_DELEGATES`; returns false for duplicates.
/// Overwrites stale grants with a list stamped by the current owner.
pub(crate) fn add_delegate(
    env: &Env,
    account_id: u64,
    owner: &Address,
    delegate: &Address,
) -> bool {
    let mut delegates = get_delegates(env, account_id, owner);
    if delegates.contains(delegate) {
        return false;
    }
    assert_with_error!(
        env,
        delegates.len() < MAX_DELEGATES,
        GenericError::RegistryCapReached
    );
    delegates.push_back(delegate.clone());
    set_delegates(env, account_id, owner, &delegates);
    true
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

**File:** contracts/controller/src/positions/debt.rs (L31-59)
```rust
/// Borrows to `to` or the authorized owner/delegate, then checks solvency.
/// Persists supply alongside debt when the check restamps supply LTVs.
pub(crate) fn process_borrow(
    env: &Env,
    caller: &Address,
    account_id: u64,
    borrows: &Vec<HubPayment>,
    to: Option<Address>,
) {
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

    let restamped = enforce_post_pool_solvency(env, &mut cache, &mut account);
```

**File:** contracts/controller/src/positions/debt.rs (L103-122)
```rust
    for (hub_asset, amount) in aggregated.iter() {
        let position = account.get_or_create_debt_position(&hub_asset);
        entries.push_back(PoolBorrowEntry {
            action: make_pool_action(&position, amount, hub_asset.clone()),
        });
    }
    let results = pool_borrow_call(env, &pool_addr, recipient, &entries);
    for_each_leg(env, &entries, &results, |entry, result| {
        merge_debt_leg(
            env,
            account,
            events::PositionAction::Borrow,
            &entry.action.hub_asset,
            LegDirection::Entry {
                asset_decimals: result.asset_decimals,
            },
            &LegOutcome::from(&result),
            cache,
        );
    });
```

**File:** contracts/controller/src/account.rs (L114-127)
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
```

**File:** contracts/controller/src/account.rs (L129-140)
```rust
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
```

**File:** contracts/controller/src/account.rs (L240-258)
```rust
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
```
