### Title
An `approve_for_all` operator can front-run revocation by issuing a persistent per-token `approve` grant to an accomplice, who then steals the entire lending account — (File: contracts/position-nft/README.md)

### Summary
The Drips M-02 class is "a delegate entrenching itself: a revoked authority can front-run revocation by granting authority to an accomplice, who restores it afterward." XOXNO Lending mitigated this for controller delegates — `add_delegate`/`remove_delegate` go through `set_account_delegate`, which calls `require_account_owner`, so a delegate cannot extend its own reach [1](#0-0) . But the same class survives through the position NFT's stock OpenZeppelin approval surface: an `approve_for_all` operator is also permitted to call `approve`, which writes a per-token `Approval(token_id)` entry keyed independently of the operator grant. Revoking the operator via `approve_for_all(owner, operator, 0)` does not clear that per-token approval, so the accomplice retains the power to `transfer_from` the token — which moves the whole account, collateral and debt included.

### Finding Description
In `contracts/position-nft`, `approve` allows `approver` to be "the owner or an operator" [2](#0-1) . The per-token approval is stored under `NFTStorageKey::Approval(token_id)`, separate from `ApprovalForAll(owner, operator)` [3](#0-2) . Revocation of an operator is `approve_for_all(owner, operator, live_until_ledger = 0)` [4](#0-3) , which only expires the operator entry — nothing enumerates and clears outstanding `Approval(token_id)` grants the operator created. Because `account_id == token_id` and transferring the token transfers the whole position with its collateral and debt [5](#0-4) , the surviving approval is equivalent to the Drips attacker's re-granted authority, except stronger: the accomplice does not re-enable the operator, it simply takes the account outright.

Attack sequence (single unprivileged operator):
1. Owner runs `approve_for_all(owner, operator, live_until_ledger)`.
2. Owner decides to revoke and submits `approve_for_all(owner, operator, 0)`.
3. Operator observes the revocation in the mempool and front-runs it with `approve(operator, accomplice, token_id, live_until_ledger)` — authorized because the operator entry is still live at that point.
4. Revocation executes; `is_approved_for_all(owner, operator)` is now false, but `get_approved(token_id) == accomplice` persists.
5. Accomplice calls `transfer_from(accomplice, owner, accomplice, token_id)`, which requires only the live per-token approval [6](#0-5)  and moves the account — all collateral and debt — to the accomplice.

The test `approved_operator_can_transfer_and_approval_is_cleared` confirms the approval alone suffices for `transfer_from` and is cleared only by a transfer, not by any operator-state change [7](#0-6) .

### Impact Explanation
Permanent theft of the user's entire position: collateral assets and any unclaimed yield move with the NFT to the accomplice, satisfying the "theft of user funds" bar. Unlike the Drips original, no ongoing battle is needed — one front-run grants an approval the owner has no single entrypoint to clear (the owner would have to discover and call `approve` again to overwrite each per-token approval, racing the accomplice's `transfer_from`).

### Likelihood Explanation
Requires the owner to have granted `approve_for_all` to an operator that turns malicious and to front-run or simply act before revocation lands — the same precondition as the Medium-severity original. Soroban transactions are fee-bid ordered and simulation reveals pending intent, so the ordering race is realistic. The trigger needs no privilege beyond the operator grant itself.

### Recommendation
Restrict `approve` so `approver` must be the token owner, not an operator (mirroring the controller's `require_account_owner` gate on `add_delegate`); alternatively or additionally, clear/ignore per-token `Approval(token_id)` entries whose `approver` is a since-revoked operator, or document and provide a `revoke_all`-style path that lets an owner clear both operator grants and operator-created token approvals in one call.

### Proof of Concept
Soroban test analogous to the provided Foundry PoC, using `position-nft` client calls as in `contracts/position-nft/src/test.rs`:

```rust
let token_id = client.mint(&owner);
let live_until = env.ledger().sequence() + 1_000;

// Owner grants operator blanket authority.
client.approve_for_all(&owner, &operator, &live_until);

// Owner submits approve_for_all(owner, operator, 0); operator front-runs
// by approving accomplice for the specific token while its operator
// grant is still live.
client.approve(&operator, &accomplice, &token_id, &live_until);

// Owner's revocation executes — operator entry is dead.
client.approve_for_all(&owner, &operator, &0u32);
assert!(!client.is_approved_for_all(&owner, &operator));

// But the per-token approval survives: accomplice takes the whole account.
assert_eq!(client.get_approved(&token_id), Some(accomplice.clone()));
client.transfer_from(&accomplice, &owner, &accomplice, &token_id);
assert_eq!(client.owner_of(&token_id), accomplice);
```

Controller-level consequence follows from `require_owner_or_delegate` resolving the current NFT owner [8](#0-7) : the accomplice, now owner, can `withdraw` the account's collateral immediately.

### Citations

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

**File:** contracts/controller/src/account.rs (L242-258)
```rust
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

**File:** contracts/position-nft/README.md (L33-41)
```markdown
`account_id == token_id`. The controller widens `u32` to `u64` on mint and
narrows back with `u32::try_from` on every other call; an id above `u32::MAX`
can never have been minted, so it resolves to `AccountNotFound`. Account id `0`
is the controller's "create a new account" sentinel, so the constructor
consumes token id 0 and the first real position is id 1.

Transferring the token transfers the whole position. Nothing in the controller
changes on transfer: the next controller call resolves the new holder and
accepts it. Collateral and debt both move with the token.
```

**File:** contracts/position-nft/README.md (L62-65)
```markdown
| `transfer` | `fn transfer(e: &Env, from: Address, to: Address, token_id: u32)` | `from` must authorize | Moves the position to `to` |
| `transfer_from` | `fn transfer_from(e: &Env, spender: Address, from: Address, to: Address, token_id: u32)` | `spender` must authorize and be `from`, approved for the token, or an operator for `from` | Moves the position to `to` |
| `approve` | `fn approve(e: &Env, approver: Address, approved: Address, token_id: u32, live_until_ledger: u32)` | `approver` must authorize and be the owner or an operator | Grants `approved` the right to move that one position until `live_until_ledger` |
| `approve_for_all` | `fn approve_for_all(e: &Env, owner: Address, operator: Address, live_until_ledger: u32)` | `owner` must authorize | Makes `operator` able to move every position `owner` holds until `live_until_ledger`; `0` revokes |
```

**File:** contracts/position-nft/README.md (L95-96)
```markdown
| `NFTStorageKey::Approval(token_id)` | temporary | Per-token approval, expires at `live_until_ledger` |
| `NFTStorageKey::ApprovalForAll(owner, operator)` | temporary | Operator approval, expires at `live_until_ledger` |
```

**File:** contracts/position-nft/src/test.rs (L146-157)
```rust
    let live_until = env.ledger().sequence() + 1_000;
    client.approve(&owner, &operator, &token_id, &live_until);
    assert_eq!(client.get_approved(&token_id), Some(operator.clone()));

    // The approved operator, not the owner, authorizes the transfer.
    client.transfer_from(&operator, &owner, &recipient, &token_id);

    assert_eq!(client.owner_of(&token_id), recipient);
    assert_eq!(client.balance(&owner), 0u32);
    assert_eq!(client.balance(&recipient), 1u32);
    // Approval does not carry over to the new owner.
    assert_eq!(client.get_approved(&token_id), None);
```
