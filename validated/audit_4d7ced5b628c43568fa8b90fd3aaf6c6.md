### Title
Stale delegate grants regain authorization after a position NFT round-trip - (File: contracts/controller/src/storage/account.rs)

### Summary
Delegate authorization is stored under the account ID and stamped with the granting owner. An NFT transfer makes the grant inactive, but does not delete it. If the NFT later returns to the original owner before another delegate update overwrites the entry, the old delegate list becomes active again. The former delegate can then withdraw or otherwise manage the account without any fresh authorization.

### Finding Description
`DelegateGrant` stores `granted_by` together with the delegate list. `get_delegates` returns that list only when `granted_by` equals the account's current NFT owner. On transfer to another owner the old grant is merely dormant; `is_owner_or_delegate` rejects it because the resolved owner no longer matches `granted_by`.

However, when the NFT is transferred back to the original owner, the stale storage entry again satisfies the `granted_by` check. No nonce, ownership epoch, or explicit cleanup prevents resurrection. The stored behavior is explicit in `DelegateGrant`: if the NFT returns to `granted_by` before a write, “the original delegate list is live again” (`common/src/types/controller.rs:63-67`).

The privileged paths then trust that revived grant:

- `is_owner_or_delegate` checks `get_delegates(env, account_id, owner)` (`contracts/controller/src/account.rs:121-127`).
- `process_withdraw` accepts an owner or delegate and sends proceeds to an arbitrary external recipient (`contracts/controller/src/positions/supply.rs:147-168`).
- Other owner/delegate-gated paths include `borrow`, `multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral`.

### Impact Explanation
A stale delegate can steal user funds after the account NFT returns to the original owner. For a debt-free or sufficiently collateralized account, the revived delegate calls `withdraw(account_id, withdrawals, Some(delegate))` and receives the account’s collateral directly. For leveraged accounts, it can also use the revived management authorization to initiate owner/delegate-only strategy operations.

This is theft of user funds reachable with only ordinary account-NFT transfers and an authenticated delegate call. No privileged controller role is required during the exploit.

### Likelihood Explanation
Exploitation requires a prior delegate grant and an account-ownership round trip back to the grantor before the intervening owner overwrites or deletes the stale `Delegates(account_id)` entry. That sequence can occur when an account is temporarily transferred, traded, escrowed, or moved between wallets while relying on NFT ownership change to invalidate prior manager access.

Likelihood is therefore moderate rather than high: the attacker cannot force the NFT to return to the grantor, but once that happens the stale authorization is automatically restored without the returning owner’s consent.

### Recommendation
Do not allow a delegate grant to survive an ownership change. Clear `ControllerKey::Delegates(account_id)` whenever ownership changes, or include an NFT ownership epoch/generation in `DelegateGrant` and increment that epoch on every position-NFT transfer. If clearing cannot be performed synchronously, ensure the position NFT exposes a monotonic transfer generation and make `get_delegates` reject grants stamped before the current generation.

### Proof of Concept
1. Governance has already marked `M` as an active position manager.
2. Owner `O` holds funded account `A` and calls `controller.add_delegate(O, A, M)`, creating `Delegates(A) = { granted_by: O, delegates: [M] }`.
3. `O` transfers position NFT `A` to address `I`. The stale grant remains in controller storage, but is inactive because `account_owner(A) == I`.
4. `I` transfers NFT `A` back to `O` and never calls `add_delegate` or `remove_delegate`, leaving the stale grant unchanged.
5. `M` calls `controller.withdraw(M, A, withdrawals, Some(M))`.
6. `require_owner_or_delegate` resolves the owner as `O`; the stale grant’s `granted_by` now matches `O` again, so `M` is accepted and receives the withdrawn collateral.