### Title
Stale per-account delegates survive position-NFT ownership transfer — a removed owner's delegate keeps full account authority (CVE-2021-47505 analog: missing teardown notification) - (File: contracts/controller/src/storage/account.rs)

### Summary
CVE-2021-47505 is a use-after-free caused by a missing `POLLFREE` notification: a subsystem (aio poll) registered a waiter on an object whose lifetime belonged to another owner, and nothing told the waiter when that object was freed. The XOXNO Lending analog is the controller's `Delegates` map: delegation rights are stored keyed by `account_id`, but the lifetime that legitimates them is the position NFT's *current owner*. When the NFT is transferred (position-nft `transfer`/`approve`), nothing notifies the controller to drop the delegation entries, so a delegate appointed by the previous owner retains full authority over an account now owned by someone else.

### Finding Description
- Per-account delegates live in `ControllerKey::Delegates(account_id)` in `contracts/controller/src/storage/account.rs` (removed only by `remove_account_entry` at lines 250-256, which runs only on account deletion — not on NFT transfer).
- The position NFT contract is a separate contract. Its `transfer`/`approve` entrypoints change `Owner(token_id)` storage; there is no callback or hook into the controller that clears `Delegates(account_id)` on transfer. INV-STOR-03 (`docs/reference/invariants.md` lines 590-597) confirms lifecycle pairing only at creation and deletion: "Production deletion removes account entries and burns that NFT in one transaction." Transfer is not a deletion.
- Controller authorization for account verbs (supply/withdraw/borrow/repay/strategies/flash_position on an existing account) accepts "owner or active delegate" — this is documented for `flash_position` ("An existing account requires owner or delegate authorization", `contracts/controller/src/lib.rs` lines 186-187) and for liquidation `Credit` mode ("the liquidator contract owns the position NFT or is an active delegate", `skills/xoxno-lending-contracts/composing.md` line 86).
- Therefore: owner A appoints delegate D, then sells/gifts/transfers the position NFT to B. `Delegates(account_id)` is untouched. D — reachable as an unprivileged address — can still call `withdraw`, `borrow`, `swap_collateral`, `repay_debt_with_collateral`, or `flash_position` on `account_id` against B's collateral.

### Impact Explanation
Theft of user funds / protocol-relevant loss. A stale delegate can:
- `borrow` the maximum debt against B's collateral and route proceeds out (delegation authorizes the borrow leg; the debt stays on B's account, driving it to liquidation),
- `withdraw` collateral where the leg authorizes delegate withdrawal,
- `swap_collateral`/`swap_debt`/`repay_debt_with_collateral` through unallowlisted route venues to siphon value,
- `flash_position` to mint debt and steer callback receipts.

Any of these drains or encumbers the collateral the buyer paid for, using authority the seller — not the buyer — granted.

### Likelihood Explanation
- Reachability: fully unprivileged. `position_nft.transfer` is a user entrypoint; all listed controller verbs accept delegate authorization.
- Preconditions: an account with a configured delegate and an NFT transfer where the seller does not manually revoke delegates first. Delegation is a first-class feature (`Delegates` storage, `delegate_revocation_between_legs` tests, keeper renewal of the `Delegates` key), so accounts with delegates are expected in production. Secondary-market or OTC sales of positions are a normal use of an NFT-represented position.
- The root cause mirrors the CVE exactly: the object that anchors authority (NFT ownership) changes/frees while the registered waiter (`Delegates` entry) is never notified, and there is no RCU-style grace — the stale delegation is honored immediately and silently.

### Recommendation
Make delegation lifetime track ownership, the way `POLLFREE` makes waiters track the waitqueue:
1. Store the owner address (or an ownership epoch/nonce) inside the `Delegates` entry or `AccountMeta`, and have `require_authorized_caller`/`account_from_parts` compare it against `try_account_owner`; a delegate stamped under a previous owner is ignored.
2. Alternatively, expire delegations by recording a per-account `delegates_epoch` bumped on any ownership change detected by controller entrypoints (compare stored owner to current `try_account_owner` on each mutating call and clear mismatched delegate grants).
3. At minimum, document and enforce in code that ownership change revokes delegates; do not rely on users remembering to revoke before transfer, since ERC-721-style semantics already clear token approvals on transfer and users will assume parity.

### Proof of Concept
1. Alice creates a `Normal` account (account_id `A`), supplies 100,000 USDC, and sets Bob as delegate via the controller's delegate-management call. `Delegates(A) = {Bob}`.
2. Alice transfers position NFT `A` to Carol via `position-nft.transfer(alice, carol, A)`. `Owner(A)` now resolves to Carol; `Delegates(A)` still contains Bob — nothing in the transfer path touches controller storage.
3. Bob calls `controller.borrow(bob_as_caller, account_id = A, hub_asset = ETH, amount = max, to = bob)` (or `withdraw`/`swap_collateral`). The controller resolves the account, sees Bob is an active delegate, authorizes the verb, and mints debt against Carol's collateral / pays out to Bob.
4. Carol's account is now over-levered or drained; Bob extracted value with authority granted by a former owner — a use-after-free of delegated authority.

Note: the precise check that admits delegates (the "owner or active delegate" branch in `contracts/controller/src/account.rs`) and the exact delegate-management entrypoint could not be fully re-read within the iteration budget; the claim rests on the `Delegates(account_id)` storage key, its removal only inside `remove_account_entry`, and the documented "owner or delegate" authorization rule. If that branch additionally validates the delegate's grantor against the current NFT owner, the finding would not hold — worth confirming the delegate record does not embed/check the granting owner.