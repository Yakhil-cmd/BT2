### Title
Stale `DelegateGrant` re-arms when the position NFT returns to the granting owner, restoring unauthorized account control - (File: contracts/controller/src/storage/account.rs)

### Summary
The controller keys delegate grants by `account_id` only and stamps them with `granted_by`. `get_delegates` authorizes a delegate whenever `granted_by` equals the current NFT owner. When the position NFT is transferred, the previous owner's grant is left in storage rather than deleted; if the NFT ever returns to the original owner, the old delegate grant silently becomes active again — the exact stale-approval-resurrection class from the OwnableSmartWallet finding.

### Finding Description
`DelegateGrant` is stored under `ControllerKey::Delegates(account_id)` and `get_delegates` filters only on `grant.granted_by == *owner` [1](#0-0) . A transfer does not clear the entry; `remove_account_entry` is the only unconditional deletion path [2](#0-1) . Authorization flows through `is_owner_or_delegate`, which accepts any `is_active` position manager listed in the live grant [3](#0-2) . Stale grants are purged only if the *new* owner calls `remove_delegate` (which deletes a grant stamped by someone else) or calls `add_delegate` (which overwrites the entry) [4](#0-3) . If the intermediate owner does neither — and they have no incentive to, since the grant is already inert for them — the grant re-activates the moment `owner_of` resolves back to `granted_by`. The README confirms the resurrection explicitly: "The stale grant stays in storage and re-arms if the token returns to `granted_by`" (contracts/position-nft/README.md, security rules).

Delegates are high-privilege: per `skills/xoxno-lending-contracts/positions.md`, "Delegates may borrow or withdraw to arbitrary recipients," and `require_owner_or_delegate` gates `withdraw`, `borrow`, `migrate_from_blend`, and `multiply` paths [5](#0-4) .

### Impact Explanation
Theft of user funds. Once the grant re-arms, the (governance-activated) position manager can call `withdraw`/`borrow` on the account and send proceeds to an arbitrary `to`/`as_to` recipient, draining collateral up to the LTV limit and beyond via borrowed funds — without the current owner's fresh authorization. This mirrors M-07: approvals an owner gave in a previous ownership epoch survive an intermediate ownership period and regain power.

### Likelihood Explanation
Requires a specific sequence: owner A delegates to an active manager, the NFT moves to B (sale, transfer, OTC position trade — the README notes a transfer "moves the collateral and the debt"), B returns it to A (or sells and it later returns), and B never calls `remove_delegate` or `add_delegate` — the common case since a foreign grant is inert for B. All steps are unprivileged holder-authorized calls (`position-nft::transfer`, `transfer_from`). Medium likelihood; Medium/High impact capped by the delegate being a whitelisted manager rather than an arbitrary address.

### Recommendation
Invalidate the grant on ownership change rather than keying validity on `granted_by`. Options: have the NFT's transfer hook (or a controller-side `sync_owner` on first touch) delete `ControllerKey::Delegates(account_id)` whenever `owner_of` differs from a stored `last_grant_owner`; or add a generation/epoch counter to `AccountMeta` bumped by a permissionless `touch_account` that any caller can invoke after a transfer, included in the `DelegateGrant` key so stale grants can never match. At minimum, purge stale grants in every entrypoint that resolves the owner (currently only the new owner's opt-in `remove_delegate`/`add_delegate` does).

### Proof of Concept
1. Alice supplies collateral; governance-activated manager M exists. Alice calls `controller::add_delegate(caller=alice, account_id, delegate=M)` — `DelegateGrant{granted_by: alice, delegates:[M]}` stored.
2. Alice calls `position_nft::transfer(alice, bob, token_id)`. The grant stays in storage; `get_delegates(id, bob)` reads empty (Bob never calls `remove_delegate` or `add_delegate`).
3. Bob calls `position_nft::transfer(bob, alice, token_id)` (round-trip, or the NFT returns via an approved `transfer_from`).
4. `owner_of(id) == alice == grant.granted_by`, so `get_delegates(id, alice)` returns `[M]` again — the grant re-arms with no fresh authorization from Alice.
5. M calls `controller::withdraw(caller=M, account_id, withdrawals=[collateral], to=M_controlled)` or `borrow(... , to=M_controlled)`; `require_owner_or_delegate` passes via the resurrected grant and funds leave Alice's account.

The unit tests already pin the building blocks: `delegates_of_previous_owner_read_as_empty` shows the grant is only filtered, not deleted, and `remove_delegate_purges_stale_grant_preventing_resurrection` confirms resurrection is possible absent the purge [6](#0-5) .

Caveat: the re-arm behavior is explicitly documented in `contracts/position-nft/README.md` and could be argued a documented design decision; it is reported because the resurrection path produces unauthorized fund movement matching the M-07 class, and the documented mitigation (new owner purging) is opt-in for a party with no incentive to invoke it.

### Citations

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

**File:** contracts/controller/src/storage/account.rs (L226-247)
```rust
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

**File:** contracts/controller/src/account.rs (L101-110)
```rust
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
```

**File:** contracts/controller/src/account.rs (L115-127)
```rust
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

**File:** contracts/controller/tests/storage/account.rs (L180-226)
```rust
fn remove_delegate_purges_stale_grant_preventing_resurrection() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(Controller, (admin,));
    let nft = setup_position_nft(&env, &contract_id);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let delegate = Address::generate(&env);
    let account_id = u64::from(position_nft::PositionNftClient::new(&env, &nft).mint(&alice));

    env.as_contract(&contract_id, || {
        assert!(add_delegate(&env, account_id, &alice, &delegate));
        assert_eq!(get_delegates(&env, account_id, &alice).len(), 1);
    });

    position_nft::PositionNftClient::new(&env, &nft).transfer(
        &alice,
        &bob,
        &u32::try_from(account_id).unwrap(),
    );

    env.as_contract(&contract_id, || {
        assert!(!remove_delegate(&env, account_id, &bob, &delegate));
        assert!(
            !env.storage()
                .persistent()
                .has(&ControllerKey::Delegates(account_id)),
            "stale grant must be purged from storage, not merely read as empty"
        );
    });

    position_nft::PositionNftClient::new(&env, &nft).transfer(
        &bob,
        &alice,
        &u32::try_from(account_id).unwrap(),
    );

    env.as_contract(&contract_id, || {
        assert_eq!(
            get_delegates(&env, account_id, &alice).len(),
            0,
            "the purged grant must not resurrect when the NFT returns to its original owner"
        );
    });
}
```
