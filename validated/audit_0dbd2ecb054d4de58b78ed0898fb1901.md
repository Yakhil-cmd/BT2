The delegate re-arm behavior looks like the strongest analog — a stale authorization persisting indefinitely and reviving. Let me verify the code.### Title
Stale delegate grants persist indefinitely and silently re-arm when the position NFT returns to the granting owner - (contracts/controller/src/storage/account.rs)

### Summary
The bug class is *excessive auth/session persistence*: an authorization that should be dead survives in storage and becomes usable again much later. XOXNO Lending's `DelegateGrant` has exactly this shape. A delegate grant is stored once under `ControllerKey::Delegates(account_id)` with a `granted_by` stamp. When the NFT (and therefore the whole account, collateral and debt) is transferred, the grant is not deleted — `get_delegates` merely filters it out because `granted_by != current owner`. If the token ever returns to the original owner, the dormant grant re-activates with no fresh consent, no expiry, and no notification.

### Finding Description
`get_delegates` returns the stored delegate list only when `grant.granted_by == owner`, so a transfer makes the previous owner's delegates inert — but `set_delegates`/`DelegateGrant` remain in persistent storage [1](#0-0) . Nothing on the NFT-transfer path clears `ControllerKey::Delegates`, and `remove_account_entry` is the only deletion outside of `remove_delegate`/`set_delegates` [2](#0-1) . The position-nft README confirms: "The stale grant stays in storage and re-arms if the token returns to `granted_by`."

An unprivileged attacker (the delegate, who may be a script/position-manager contract) can exploit the dormancy window:

1. Alice owns account `A`, calls `add_delegate(alice, A, D)`. D (an authorized position manager / script) can now `borrow` and `withdraw` on `A`.
2. Alice transfers NFT `A` to Bob (sale, lending of the position, collateralization elsewhere). The grant goes dormant but is never deleted. Alice reasonably believes her delegation relationship ended with the transfer.
3. Bob, the interim owner, likely never inspects `Delegates(A)` — and even if he wanted to, cleaning it requires him to call `remove_delegate` (which does delete a mismatched grant, `account.rs:236-238`), something there is no prompt or requirement to do.
4. The NFT returns to Alice — e.g., Bob sells it back, or Bob transfers it to an address Alice controls as part of any ordinary NFT round-trip. The instant `owner_of(A) == granted_by` again, D's grant is live.
5. D calls `borrow(account A, …)` and `withdraw(account A, …)` — drains newly added collateral or borrows against the account — without Alice ever re-authorizing D.

The harness tests pin both halves of the behavior: removed/deactivated grants block `borrow`/`withdraw` immediately, but a still-stored grant "re-arms" the moment its authority condition is satisfied again [3](#0-2) .

### Impact Explanation
A re-armed delegate can execute the owner-gated verbs (`borrow`, `withdraw`) on an account whose current owner never re-consented, enabling theft of user funds (withdrawing free collateral to the delegate-chosen recipient, or borrowing assets against the account collateral). The window is unbounded — the grant persists for as long as persistent storage lives and can revive months later.

### Likelihood Explanation
Requires an ownership round-trip back to the granting address while the stale grant survives. That is a normal, reachable flow: NFT positions are transferable by design, grants are common for keeper/manager contracts, and nothing forces an interim owner to purge `Delegates`. No oracle manipulation, privileged role, or racing is needed.

### Recommendation
- Delete `ControllerKey::Delegates(account_id)` (or write a tombstone invalidating all grants) whenever effective NFT ownership changes — e.g., have the controller clear the grant on the first account-touching call that observes `owner != grant.granted_by` epoch change, or store an ownership generation counter alongside `granted_by`.
- Alternatively, treat re-acquisition as a new ownership epoch: stamp grants with an epoch/nonce that increments on transfer, so a dormant grant can never match again.
- At minimum, document to integrators that interim owners must call `remove_delegate` to permanently kill stale grants, and add an expiry/`live_until_ledger` field to `DelegateGrant` matching the NFT approval model (`live_until_ledger` in `approve`/`approve_for_all`).

### Proof of Concept
```rust
// 1. Alice owns account A; grants delegate D (an authorized position manager).
t.ctrl_client().set_position_manager(&runner, &true);
t.ctrl_client().add_delegate(&alice, &account, &runner);

// 2. Alice transfers NFT A to Bob. Grant becomes dormant but stays in storage
//    (ControllerKey::Delegates(account) untouched; granted_by == alice).
position_nft.transfer(&alice_addr, &bob_addr, &account);
// D is correctly blocked while Bob owns the token (NOT_AUTHORIZED on borrow).

// 3. Bob never calls remove_delegate. NFT returns to Alice by any ordinary path.
position_nft.transfer(&bob_addr, &alice_addr, &account);

// 4. The stale grant re-arms silently: get_delegates matches granted_by == owner.
//    D borrows/withdraws on Alice's account with no fresh consent.
t.run_script(&runner, &vec![&t.env, borrow_op(&t, account, "ETH", amt, None)])
    .expect("stale grant re-armed without Alice re-authorizing");
```
This mirrors `deactivating_the_manager_kills_a_stored_grant_immediately` in `tests/test-harness/tests/composition/delegate_revocation_between_legs.rs`, which already demonstrates that a stored-but-inactive grant re-arms when its gating condition is restored — here the restored condition is `granted_by == owner` instead of manager activation.

### Citations

**File:** contracts/controller/src/storage/account.rs (L176-181)
```rust
pub(crate) fn get_delegates(env: &Env, account_id: u64, owner: &Address) -> Vec<Address> {
    get_user::<DelegateGrant>(env, &ControllerKey::Delegates(account_id))
        .filter(|grant| grant.granted_by == *owner)
        .map(|grant| grant.delegates)
        .unwrap_or_else(|| Vec::new(env))
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

**File:** tests/test-harness/tests/composition/delegate_revocation_between_legs.rs (L51-75)
```rust
fn deactivating_the_manager_kills_a_stored_grant_immediately() {
    let mut t = LendingTest::new().standard_two_asset_dust_disabled();
    t.supply(BOB, "ETH", 100.0);
    t.supply(ALICE, "USDC", 10_000.0);
    let account = t.account_id(ALICE);
    let runner = t.deploy_script_runner();
    let alice = t.get_or_create_user(ALICE);
    t.ctrl_client().set_position_manager(&runner, &true);
    t.ctrl_client().add_delegate(&alice, &account, &runner);
    t.ctrl_client().set_position_manager(&runner, &false);
    assert_contract_error(
        t.run_script(
            &runner,
            &vec![&t.env, borrow_op(&t, account, "ETH", U / 10, None)],
        )
        .map(|_| ()),
        errors::NOT_AUTHORIZED,
    );
    t.ctrl_client().set_position_manager(&runner, &true);
    t.run_script(
        &runner,
        &vec![&t.env, borrow_op(&t, account, "ETH", U / 10, None)],
    )
    .expect("reactivation re-arms the still-stored grant");
}
```
