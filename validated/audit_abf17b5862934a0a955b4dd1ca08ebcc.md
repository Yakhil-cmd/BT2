### Title
Stale delegate grants reactivate after a position NFT round-trip, allowing collateral theft - (File: contracts/controller/src/storage/account.rs)

### Summary
Controller delegate grants are keyed only by `account_id` and stamped with the granting owner's address, so an NFT transfer disables them temporarily but does not rotate or invalidate the authorization epoch. [1](#0-0)  If the NFT later returns to the original owner before an intervening owner writes or deletes the delegate entry, the old delegates become valid again without a new grant from that owner. [2](#0-1) 

### Finding Description
`get_delegates` loads `ControllerKey::Delegates(account_id)` and returns the stored list whenever `grant.granted_by` equals the current NFT owner. [1](#0-0)  `is_owner_or_delegate` then authorizes any still-active position manager contained in that list. [3](#0-2)  An NFT transfer only changes `owner_of(account_id)`; it does not remove or version the controller's stored grant, so `Alice -> Bob -> Alice` restores the grant originally stamped by Alice. [4](#0-3) 

The revived delegate can call `withdraw(caller=delegate, account_id, withdrawals, to=Some(delegate))`: `process_withdraw` authenticates the delegate, accepts the stale grant through `require_owner_or_delegate`, accepts an arbitrary external recipient, and interprets a zero withdrawal leg as a full withdrawal. [5](#0-4)  The same revived authority reaches `borrow`, which can send newly borrowed pool assets to the delegate while leaving the debt on the victim's account. [6](#0-5) 

### Impact Explanation
A previously delegated position manager can steal the account's withdrawable collateral or extract the maximum borrowable value after the NFT returns to the grantor, even though that owner never re-approved the delegate for the new ownership period. [7](#0-6)  This results in direct theft of user funds for debt-free collateral and unauthorized debt creation plus asset theft for collateralized accounts. [8](#0-7) 

### Likelihood Explanation
The exploit requires an account that previously granted an active position manager, an NFT transfer away from that owner, no intervening owner delegate write, and a later transfer back to the grantor. [2](#0-1)  Those conditions are externally reachable through ordinary `add_delegate`, NFT `transfer`/`transfer_from`, and controller `withdraw` or `borrow` calls, but the attacker cannot force the victim's NFT ownership changes alone. [9](#0-8) 

### Recommendation
Bind delegate authorization to an ownership generation rather than only the owner's address. Store an ownership epoch in account metadata, lazily increment it whenever the controller observes that `owner_of(account_id)` differs from the last recorded owner, and stamp `DelegateGrant` with both `granted_by` and that epoch. [10](#0-9)  Reject delegates whose stored epoch differs from the current epoch in `is_owner_or_delegate`, so every transfer permanently invalidates grants made under earlier ownership sessions. [11](#0-10) 

### Proof of Concept
1. Alice owns funded `account_id`; governance has marked Mallory as an active position manager. [12](#0-11) 
2. Alice calls `add_delegate(Alice, account_id, Mallory)`, storing `{granted_by: Alice, delegates: [Mallory]}`. [13](#0-12) 
3. Alice transfers position NFT `account_id` to Bob; Mallory is inactive because `granted_by != Bob`. [14](#0-13) 
4. Bob performs no `add_delegate` or `remove_delegate`, then transfers the same NFT back to Alice. [4](#0-3) 
5. The stored grant again matches `granted_by == Alice`, so `is_owner_or_delegate(account_id, Mallory, Alice)` returns true. [3](#0-2) 
6. Mallory submits `withdraw(Mallory, account_id, [(collateral_hub_asset, 0)], Some(Mallory))`; the zero amount requests the full collateral leg and pays it to Mallory. [5](#0-4)

### Citations

**File:** contracts/controller/src/storage/account.rs (L176-180)
```rust
pub(crate) fn get_delegates(env: &Env, account_id: u64, owner: &Address) -> Vec<Address> {
    get_user::<DelegateGrant>(env, &ControllerKey::Delegates(account_id))
        .filter(|grant| grant.granted_by == *owner)
        .map(|grant| grant.delegates)
        .unwrap_or_else(|| Vec::new(env))
```

**File:** contracts/controller/src/storage/account.rs (L183-198)
```rust
/// Stores delegates stamped by the granting owner and renews user TTL;
/// deletes the entry when the list is empty.
fn set_delegates(env: &Env, account_id: u64, owner: &Address, delegates: &Vec<Address>) {
    let key = ControllerKey::Delegates(account_id);
    if delegates.is_empty() {
        env.storage().persistent().remove(&key);
    } else {
        set_user(
            env,
            &key,
            &DelegateGrant {
                granted_by: owner.clone(),
                delegates: delegates.clone(),
            },
        );
    }
```

**File:** contracts/controller/src/storage/account.rs (L203-220)
```rust
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

**File:** common/src/types/controller.rs (L63-67)
```rust
/// A delegate list stamped with the owner who granted it. The grant is live only while
/// `granted_by` owns the account's NFT: after an NFT transfer, `get_delegates` reads it as
/// empty for the new owner. The new owner's next `add_delegate` or `remove_delegate`
/// overwrites or deletes the stale entry. If the NFT returns to `granted_by` before such a
/// write, the original delegate list is live again.
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

**File:** contracts/controller/src/account.rs (L129-139)
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
```

**File:** contracts/controller/src/account.rs (L251-257)
```rust
    if add {
        // Reject dormant grants that could gain authority on later manager activation.
        assert_with_error!(
            env,
            storage::get_position_manager(env, delegate).is_some_and(|c| c.is_active),
            GenericError::NotAuthorized
        );
```

**File:** contracts/position-nft/README.md (L174-179)
```markdown
**Delegates lapse on transfer.** The controller stores a `DelegateGrant`
stamped with the `granted_by` address. `get_delegates` returns an empty list
unless `granted_by` equals the current NFT owner, so a transfer disables the
old holder's delegates immediately. The stale grant stays in storage and
re-arms if the token returns to `granted_by`. The next holder's `add_delegate`
overwrites it and `remove_delegate` deletes it.
```

**File:** contracts/controller/src/positions/supply.rs (L147-157)
```rust
    validation::require_authorized_caller(env, caller);

    let mut account = storage::get_account(env, account_id);
    require_owner_or_delegate(env, account_id, caller, &account.owner);

    let recipient = to.unwrap_or_else(|| caller.clone());
    let mut cache = Context::new(env);
    require_external_recipient(env, &mut cache, &recipient);
    let aggregated = payments::aggregate_payments(env, withdrawals, payments::ZeroLeg::MeansAll);

    let paid = settle_withdraw(env, &mut account, &recipient, &aggregated, &mut cache);
```

**File:** contracts/controller/src/positions/debt.rs (L40-47)
```rust
    validation::require_authorized_caller(env, caller);

    let mut account = storage::get_account(env, account_id);
    require_owner_or_delegate(env, account_id, caller, &account.owner);

    let recipient = to.unwrap_or_else(|| caller.clone());
    let mut cache = Context::new(env);
    require_external_recipient(env, &mut cache, &recipient);
```

**File:** contracts/controller/src/positions/debt.rs (L57-65)
```rust
    settle_borrow(env, &mut account, &recipient, &aggregated, &mut cache);

    let restamped = enforce_post_pool_solvency(env, &mut cache, &mut account);
    let sides = if restamped {
        PositionSides::Both
    } else {
        PositionSides::Debt
    };
    finalize_position_flow(env, account_id, &account, &mut cache, sides, false);
```

**File:** docs/reference/endpoints.md (L41-49)
```markdown
| `renew_account(caller: Address, account_id: u64)` | NFT owner | open | Renew account and NFT ownership storage. |
| `add_delegate(caller: Address, account_id: u64, delegate: Address)` | NFT owner | gated | Grant only to active approved manager; maximum 16. |
| `remove_delegate(caller: Address, account_id: u64, delegate: Address)` | NFT owner | open | Revoke grant. |

### Accounts and authorization

Account id `0` creates an account on `supply`, `multiply`, `flash_position`, `migrate_from_blend`, and liquidation with `Credit(0)`. An account's spoke binding is permanent. `multiply` and `flash_position` require Multiply, Long or Short mode, and an existing account must match the requested mode. Blend migration creates a Normal account; an existing destination need not be Normal.

Delegates belong to the granting owner. An NFT transfer disables that owner's grants; a transfer back can reactivate them unless a later owner has replaced or deleted the list. NFT ownership, including control of collateral and the debt obligation, transfers atomically.
```

**File:** tests/test-harness/tests/controller/position_nft.rs (L81-92)
```rust
#[test]
fn transfer_revokes_old_owners_delegates() {
    let mut t = LendingTest::new().with_market(usdc_preset()).build();
    t.supply(ALICE, "USDC", 1_000.0);
    let account_id = t.account_id(ALICE);
    t.enable_delegate(ALICE, "MANAGER", account_id);

    t.nft_transfer(ALICE, BOB, account_id);

    // The manager's grant was stamped by ALICE; with BOB as owner it is dead.
    let result = t.try_borrow_as_to("MANAGER", account_id, "USDC", 10.0, "MANAGER");
    assert_contract_error(result, errors::NOT_AUTHORIZED);
```
