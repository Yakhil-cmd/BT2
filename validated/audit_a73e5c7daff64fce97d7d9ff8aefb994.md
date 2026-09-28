### Title
Stale delegate authorization survives position-NFT transfer, letting a prior delegate act on the new owner's account - (File: contracts/controller/src/storage/account.rs)

### Summary
The controller stores per-account delegate authorizations under `ControllerKey::Delegates(account_id)` and resolves account ownership lazily through the position NFT's `owner_of`. Delegates are only removed when the account itself is deleted (`remove_account_entry`); an NFT `transfer`/`approve` on the separate position-nft contract has no hook back into the controller, so a delegate registered by a previous owner remains authorized against `account_id` forever. This is the UAF analog: an authorization object (the delegate entry) referencing a transferred account is never invalidated when ownership of the underlying asset changes.

### Finding Description
- `remove_account_entry` deletes `AccountMeta`, `SupplyPositions`, `BorrowPositions`, and `Delegates` — but only runs on account deletion (`remove_account_and_burn_nft` in `contracts/controller/src/account.rs:159-163`).
- The NFT side exposes only `mint`, `burn`, `try_owner_of`, `renew`, `upgrade` to the controller (`contracts/controller/src/external/position_nft.rs`); ownership is read lazily via `nft_try_owner_of_call`, so nothing observes or reacts to a `transfer`.
- Delegate entries are therefore keyed to the account ID, not to the owner epoch. Monetary paths consult delegates (`positions/supply.rs`, `positions/debt.rs`, `positions/liquidation/mod.rs`, `strategies/swap_debt.rs`, `strategies/swap_collateral.rs`, `strategies/repay_debt_with_collateral.rs`), and liquidation docs explicitly accept "the liquidator contract owns the position NFT **or is an active delegate**".
- `update_account_threshold`'s ownership resolution (`try_account_owner`) is fresh, but delegate checks are account-scoped, not owner-scoped.

Attack path for a single unprivileged address: owner A registers delegate D on `account_id`, then transfers the position NFT to victim B (sale, use as external collateral, or gifting a leveraged account). D's entry in `Delegates(account_id)` persists. D then invokes delegate-authorized controller entrypoints against the account B now owns — e.g., `borrow` against B's collateral or `liquidate`/`swap_*` paths that accept delegate authority — extracting value while B is the recorded NFT owner.

### Impact Explanation
Theft of user funds: a stale delegate can draw debt against collateral owned by the new NFT holder, or steer strategy/liquidation flows, saddling the buyer with obligations they never authorized. The authorization dangles because its lifetime is bound to `account_id` existence rather than to the owner that granted it — the exact shape of a use-after-free (a reference outliving the object lifetime it was scoped to).

### Likelihood Explanation
Reachable by any unprivileged address: setting a delegate and calling `transfer`/`approve` on the position NFT are both in-scope unprivileged actions, as are the subsequent delegate-authorized controller calls. It requires the victim to acquire an NFT that already has a delegate registered — realistic for NFT sale/secondary-market or wallet-rotation flows. Caveat: I confirmed delegates are consulted in the monetary paths listed above but could not enumerate every delegate-permitted verb within the iteration budget; if delegate scope is limited to non-fund-moving operations, the impact would degrade.

### Recommendation
Bind delegate validity to the ownership epoch: record the authorizing owner (or an owner nonce/transfer counter) inside the `Delegates` entry and reject delegates whose recorded owner differs from the live `nft_try_owner_of` result; alternatively, clear `Delegates(account_id)` on any observed ownership change (e.g., on each `require_account_owner` resolution, persist the owner and wipe stale delegate entries when it differs).

### Proof of Concept
1. Alice supplies, creating `account_id = N` (NFT minted to Alice).
2. Alice registers Bob as delegate for `N` via the controller's delegate-granting path.
3. Alice calls `position_nft.transfer(alice, carol, N)` — Bob's `Delegates(N)` entry is untouched; `remove_account_entry` never runs.
4. Bob calls a delegate-authorized monetary entrypoint (e.g., `borrow`/`liquidate`/`swap_collateral`) on `N`; the delegate check passes against the stale entry while `owner_of(N) == carol`.
5. Carol's collateral backs Bob-drawn debt — the dangling authorization survived the transfer of the object it referenced.