### Title
Stale delegate grants reactivate after NFT ownership round-trip, enabling collateral theft - (File: contracts/controller/src/storage/account.rs)

### Summary
Controller delegate grants are keyed only by the address that created them, not by an NFT ownership generation. If an account NFT is transferred away and later returned, a grant created by the original owner becomes active again without a new delegation. The former delegate can then act as the account owner-delegate and withdraw collateral or borrow proceeds to itself.

### Finding Description
`get_delegates` filters the stored `DelegateGrant` solely by `grant.granted_by == current NFT owner`. It does not bind the grant to an ownership epoch, transfer counter, or immutable possession session. Consequently, ownership changes only mask the grant; they do not permanently invalidate it. When the NFT returns to `granted_by`, the old grant is returned by `get_delegates` again.

A stale grant is deleted only if a subsequent owner explicitly calls `remove_delegate`, or overwritten if they call `add_delegate`. If the interim owner performs neither action, the original grant survives the round-trip unchanged.

`is_owner_or_delegate` then accepts the stale delegate when that address is an active position manager. `withdraw` resolves the current NFT owner, requires owner-or-delegate authorization, and permits an arbitrary external `to` recipient. `borrow` similarly permits an arbitrary recipient.

### Impact Explanation
This enables theft of user funds and unauthorized debt creation.

For example, a user previously delegates an approved position manager and later transfers the account NFT to that manager as part of a sale, migration, collateral workflow, or contract interaction. If the manager transfers the NFT back without modifying the delegate list, the user's earlier grant silently reactivates. The manager can then call `withdraw` to send the account's withdrawable collateral to itself, or call `borrow` to extract newly borrowed assets while leaving the debt on the victim's account.

The attack is bounded by the account's post-operation solvency checks, but it can steal all collateral from a debt-free account or extract all available borrowing capacity from a collateralized account.

### Likelihood Explanation
The vulnerable sequence requires:

1. The victim previously grants a delegate that remains an active position manager.
2. The account NFT is transferred to another owner.
3. The NFT is later transferred back to the original owner.
4. No intervening owner calls `remove_delegate` or `add_delegate` for the account.

NFT ownership transfer is an intended user-facing operation, and the delegate grant is not explicitly revoked during transfer. A delegated manager that receives and returns the NFT can trigger the stale grant without obtaining fresh authorization from the victim.

### Recommendation
Bind delegate grants to an NFT ownership generation rather than only to `granted_by`.

For example:

- Add a monotonically increasing `ownership_revision` or transfer counter to the position NFT.
- Store that revision in `DelegateGrant` when `add_delegate` is called.
- Require both `granted_by == current_owner` and `stored_revision == current_revision` in `get_delegates`.
- Alternatively, make the position NFT notify the controller on every transfer so the controller can delete `ControllerKey::Delegates(account_id)`.

Until contract changes are deployed, users and integrations should explicitly purge stale grants with `remove_delegate` after receiving an account NFT.

### Proof of Concept
Conceptual sequence:

```rust
// 1. Alice owns an account holding USDC collateral.
let account_id = controller.supply(
    alice,
    0,
    spoke_id,
    vec![(usdc_hub_asset, collateral_amount)],
);

// 2. Alice grants an approved position manager.
controller.add_delegate(alice, account_id, manager);

// 3. Alice transfers the account NFT to the manager.
position_nft.transfer(alice, manager, account_id as u32);

// 4. While the manager owns the NFT, it does not alter the stale grant.
// 5. The manager transfers the NFT back to Alice.
position_nft.transfer(manager, alice, account_id as u32);

// 6. Alice's old grant is active again because `granted_by == alice`.
// 7. The manager withdraws Alice's collateral to itself.
controller.withdraw(
    manager,
    account_id,
    vec![(usdc_hub_asset, 0)], // 0 withdraws all
    Some(manager),
);
```

For a collateralized account, the stale delegate can instead first call:

```rust
controller.borrow(
    manager,
    account_id,
    vec![(debt_hub_asset, maximum_safe_amount)],
    Some(manager),
);
```

The call succeeds after the NFT round-trip even though Alice did not re-authorize the manager after regaining ownership.