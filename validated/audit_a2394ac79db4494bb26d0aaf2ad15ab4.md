### Title
Stale `DelegateGrant` resurrects spending authority when the position NFT returns to its original owner - (File: contracts/controller/src/storage/account.rs)

### Summary

The kernel analog is a released reference silently re-arming a resource that is still attached. In XOXNO Lending, a `DelegateGrant` is keyed only by `account_id` and stamped with `granted_by` (the owner at grant time), not by any transfer epoch. When the NFT moves to a new owner the grant reads as dead, but it is **not deleted** — if the NFT is ever transferred back to `granted_by`, the old delegate list becomes live again with no fresh authorization. A delegate can then call `borrow`/`withdraw` paying an arbitrary `to` address, draining the account's borrowing power and collateral.

### Finding Description

`get_delegates` filters the stored grant by `grant.granted_by == *owner` and otherwise returns an empty list, leaving the entry in persistent storage (contracts/controller/src/storage/account.rs:176-181):

```rust
get_user::<DelegateGrant>(env, &ControllerKey::Delegates(account_id))
    .filter(|grant| grant.granted_by == *owner)
    .map(|grant| grant.delegates)
```

Only three writes can clear the stale entry: the original owner's `remove_delegate`, or an intervening owner's `add_delegate`/`remove_delegate` (`set_delegates` overwrites; `remove_delegate` deletes a foreign grant at lines 236-238). If the intermediate owner never touches delegates — the common case, since `get_delegates` reports the list as empty for them and nothing prompts a purge — the grant survives intact.

The only thing standing between the stale grant and live authority is `is_owner_or_delegate`, which resolves the *current* NFT owner and calls `get_delegates(env, account_id, &owner)`. The moment `owner_of(account_id)` equals `granted_by` again, the filter passes and every stored delegate regains owner-equivalent authority over `borrow`, `withdraw`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `multiply`, `flash_position`, and `migrate_from_blend`. Per the endpoint reference, delegates "can choose external payout recipients" via `to: Option<Address>` — they are not constrained to acting in the owner's interest.

There is no re-auth checkpoint: no nonce, epoch, or re-acknowledgement is required when ownership returns. The grant is treated as still referenced by its original binder even though that binding was released.

### Impact Explanation

Theft of user funds. Once re-armed, a delegate can `borrow` to the maximum LTV with `to` set to their own address, or `withdraw` all collateral to themselves — imposing debt on the victim's account while taking the tokens. If the account is insolvent-adjacent the delegate can also drive it through self-liquidation. No privileged role, oracle manipulation, or contract upgrade is needed; the attacker only needs to have once been granted delegation by any address that later regains the NFT.

### Likelihood Explanation

Requires a specific sequence but is fully unprivileged:

1. Alice calls `add_delegate(M)` while M is a governance-approved active position manager.
2. The NFT leaves Alice — she sells it, or an NFT-level `approve`/`approve_for_all` operator she authorized moves it (approval is a standard in-scope entrypoint and hands over the whole account).
3. The NFT returns to Alice — the sale unwinds, the operator transfers it back, or it round-trips through any holder who never calls `add_delegate`/`remove_delegate` (the documented happy path where the grant stays in storage).
4. M, whose grant Alice reasonably believed dead since the transfer, calls `borrow(account_id, ..., to = M)` and takes the funds.

The `transfer_revokes_prior_owner_and_delegates` test only covers the intermediate-owner state; `remove_delegate_purges_stale_grant_preventing_resurrection` proves resurrection happens when the intervening owner does *not* purge. Nothing on the NFT `transfer` path notifies the controller to wipe `Delegates(account_id)`, because the NFT contract cannot call back into the controller and `transfer` is unauthenticated from the controller's perspective.

### Recommendation

Bind grants to an ownership epoch rather than the `granted_by` address, or actively invalidate on transfer:

- Store a monotonically increasing `ownership_epoch` in `AccountMeta`, bumped whenever the controller observes an owner change (e.g., in `account_owner`/a lazy check at `require_owner_or_delegate`), and stamp `DelegateGrant { granted_by, epoch, delegates }`; `get_delegates` requires both to match. This makes resurrection structurally impossible, not just unlikely.
- Alternatively, lazily purge: in `get_delegates`, when `grant.granted_by != *owner`, delete the entry instead of merely filtering it — matching the existing `remove_delegate` purge semantics so a stale grant can never re-arm.

### Proof of Concept

Sequence against `contracts/controller` (harness-style):

```rust
// 1. Alice holds account NFT, supplies collateral.
t.supply(ALICE, "USDC", 100_000.0);
let account_id = t.account_id(ALICE);

// 2. M is a registered active position manager; Alice delegates.
t.enable_delegate(ALICE, "MANAGER", account_id);

// 3. NFT leaves Alice (sale, or an operator she approved moves it).
t.nft_transfer(ALICE, BOB, account_id);
//    get_delegates(account_id, BOB) == [] — grant looks dead.
//    BOB never calls add_delegate/remove_delegate, so the stored
//    DelegateGrant{granted_by: ALICE, delegates:[MANAGER]} survives.

// 4. NFT returns to Alice.
t.nft_transfer(BOB, ALICE, account_id);
//    owner == ALICE == grant.granted_by -> filter passes -> grant live.

// 5. M borrows to self against Alice's collateral without re-authorization.
t.borrow_as_to("MANAGER", account_id, "USDC", 50_000.0, "MANAGER");
//    Alice's account now carries the debt; MANAGER holds the tokens.
```

Root cause: `DelegateGrant` stores `granted_by: Address` only (common/src/types/controller.rs:69-73), `get_delegates` filters without deleting (contracts/controller/src/storage/account.rs:176-181), and no transfer hook clears `ControllerKey::Delegates(account_id)`, so a released authorization reference silently re-binds when `owner_of` again equals `granted_by`.