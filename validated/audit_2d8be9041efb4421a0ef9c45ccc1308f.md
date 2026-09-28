### Title
Stale delegate grants stamped by owner address re-arm after an NFT round-trip, letting a dormant manager drain a re-acquired account — (File: contracts/controller/src/storage/account.rs)

### Summary
Like CVE-2017-1000153's password-reset link that stays valid after the user's email changes, controller delegate grants are keyed to the *value* of the owner address rather than to an ownership epoch. A `DelegateGrant` stamped `granted_by = A` becomes inactive the moment the position NFT leaves `A`, but it is never invalidated: if token `account_id` ever returns to `A`, the same grant silently reactivates and the delegate regains full borrow/withdraw authority over the account without any new authorization from `A`. [1](#0-0) 

### Finding Description
Account authority on the controller is resolved live from the position NFT (`owner_of(account_id)`); the owner is never cached. Delegate grants live in `ControllerKey::Delegates(account_id)` storage as `DelegateGrant` records stamped with `granted_by`, the granting owner's address. `get_delegates` filters grants by `granted_by == current_owner`, so a grant disappears from view on transfer — but it is not deleted. The documented semantics state it plainly: "The stale grant stays in storage and re-arms if the token returns to `granted_by`. The next holder's `add_delegate` overwrites it and `remove_delegate` deletes it." [1](#0-0) 

The tests pin this shape: `delegates_of_previous_owner_read_as_empty` shows the grant persists in storage while reading empty for the new owner, and `remove_delegate_purges_stale_grant_preventing_resurrection` shows resurrection is only prevented if an intervening owner explicitly calls `remove_delegate` — a call the intervening owner has no reason to make, since `get_delegates` returns `[]` for them and nothing signals the dormant grant exists. [2](#0-1) [3](#0-2) 

Delegates are not constrained to act in the owner's interest: they "can borrow/withdraw to their chosen recipient within account gates," so a re-armed grant is equivalent to full drainage authority over the account's collateral. [4](#0-3) 

Attack sequence reachable by an unprivileged holder of an activated position-manager grant:

1. `A` owns `account_id` holding collateral and calls `add_delegate` granting manager `M` (e.g., a yield/automation product). `M` is registered via `set_position_manager` with `is_active`.
2. `A` transfers the position NFT to `B` (sells the position on any marketplace, or uses it as a transferrable wrapper). The grant goes dormant but remains in storage; `B` sees an empty delegate list.
3. `B` later transfers the same `account_id` back to `A` — `A` buys back the position, or `M`/an accomplice who acquired the token legitimately routes it back to `A` (transfer only needs the current holder's auth; `B` can be `M`'s own account that bought the NFT).
4. The moment `owner_of(account_id) == A` again, `is_owner_or_delegate` passes for `M` because `granted_by == A`. `M` calls `borrow`/`withdraw` on `account_id` with `to = M`, extracting the collateral now economically owned by `A`. [5](#0-4) 

The bug class maps exactly: an authorization artifact bound to a mutable attribute (owner address ≙ email address) is not invalidated when the attribute changes, and becomes live again when the attribute's value recurs — the emailed reset link that still works after the email change.

### Impact Explanation
Theft of user funds. When the NFT returns to `A`, `M` can borrow against all of `A`'s re-acquired collateral and withdraw to an arbitrary recipient, or withdraw supplied assets directly, leaving `A` with an account holding the debt while `M` holds the proceeds. `A` never re-consented — in `A`'s view the grant died when the position was sold — and an intervening owner cannot see or clean the dormant grant because `get_delegates` filters it out for them.

### Likelihood Explanation
Requires three conditions: `A` previously granted the delegate (normal use of position managers), `A` re-acquires the *same* `account_id` (the account id is the token id, so this is plausible on secondary markets or via the attacker steering the token back), and the delegate is still globally active. No privileged action is needed during the exploit window — only ordinary NFT transfers and the delegate's normal `borrow`/`withdraw` calls. The main mitigation is social: the behavior is documented in the position-nft README and threat model, which weakens novelty but does not prevent the theft path; nothing on-chain warns the re-acquiring owner.

### Recommendation
Invalidate delegate grants on ownership change rather than filtering by `granted_by` at read time. Options: stamp grants with a per-account transfer epoch (increment a counter on every NFT transfer via a controller hook or by storing the block/ledger of first ownership change) and require `epoch` match; or have `add_delegate`/`remove_delegate` and the ownership-resolution path (`try_account_owner` consumers) purge grants whose `granted_by` differs from the current owner instead of merely hiding them. At minimum, `get_delegates` should expose dormant grants to the current owner so a buyer can call `remove_delegate` before the token returns to `granted_by`.

### Proof of Concept
```rust
// Setup: Alice supplies USDC, activates manager M, grants delegate.
let account_id = seed_account(&env, &controller, &nft, &alice);
set_position_manager(&env, &manager, &PositionManagerConfig { is_active: true });
add_delegate(&env, account_id, &alice, &manager);

// 1. Alice sells/transfers the position NFT to Bob.
nft_client.transfer(&alice, &bob, &account_id_u32);
assert_eq!(get_delegates(&env, account_id, &bob).len(), 0); // Bob sees nothing; grant persists in storage
assert!(!is_owner_or_delegate(&env, account_id, &manager, &bob));

// 2. Bob never calls remove_delegate (nothing to remove from his view).
//    The NFT is later transferred back to Alice — e.g., Bob sells it back.
nft_client.transfer(&bob, &alice, &account_id_u32);

// 3. The stale grant re-arms silently.
let owner = account_owner(&env, account_id); // alice
assert!(is_owner_or_delegate(&env, account_id, &manager, &owner)); // BUG: resurrected grant

// 4. Manager drains: borrow/withdraw on account_id with to = manager,
//    without any fresh authorization from Alice.
```

### Citations

**File:** contracts/position-nft/README.md (L174-179)
```markdown
**Delegates lapse on transfer.** The controller stores a `DelegateGrant`
stamped with the `granted_by` address. `get_delegates` returns an empty list
unless `granted_by` equals the current NFT owner, so a transfer disables the
old holder's delegates immediately. The stale grant stays in storage and
re-arms if the token returns to `granted_by`. The next holder's `add_delegate`
overwrites it and `remove_delegate` deletes it.
```

**File:** contracts/controller/tests/storage/account.rs (L143-175)
```rust
fn delegates_of_previous_owner_read_as_empty() {
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
        assert_eq!(
            get_delegates(&env, account_id, &bob).len(),
            0,
            "a grant stamped by the previous owner must read as empty for the new owner"
        );
        assert!(add_delegate(&env, account_id, &bob, &delegate));
        assert_eq!(get_delegates(&env, account_id, &bob).len(), 1);
    });
}
```

**File:** contracts/controller/tests/storage/account.rs (L177-226)
```rust
/// The new owner's `remove_delegate` deletes a previous owner's grant and returns `false`.
/// The grant stays deleted when the NFT returns to the previous owner.
#[test]
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

**File:** docs/explanation/threat-model.md (L81-87)
```markdown
An account delegate also needs active global position-manager registration.
Its grant is stamped with the granting owner's address, not a transfer epoch:
it becomes inactive while someone else holds the NFT and can revive if the
NFT returns before an intervening owner updates delegates. Owner revocation
is immediate; global deactivation takes effect when governance executes it.
Delegates can borrow/withdraw to their chosen recipient within account gates.
Those gates do not constrain them to acting in the owner's economic interest.
```

**File:** contracts/controller/tests/helpers/account.rs (L420-431)
```rust
    env.as_contract(&contract_id, || {
        let owner = crate::storage::account_owner(&env, account_id);
        assert_eq!(owner, bob);
        // Old owner and the grant they made are both dead.
        assert!(!is_owner_or_delegate(&env, account_id, &alice, &owner));
        assert!(!is_owner_or_delegate(&env, account_id, &manager, &owner));
        // New owner works, and a fresh grant by the new owner works.
        assert!(is_owner_or_delegate(&env, account_id, &bob, &owner));
        assert!(crate::storage::add_delegate(
            &env, account_id, &bob, &manager
        ));
        assert!(is_owner_or_delegate(&env, account_id, &manager, &owner));
```
