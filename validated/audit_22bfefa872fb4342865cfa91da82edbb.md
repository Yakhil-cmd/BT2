### Title
Stale `account.owner` lets a previous NFT holder bypass position ownership checks after `position-nft` transfer - ([File: contracts/controller/src/account.rs])

### Summary
The H2O advisory is an access-control bypass: the IP-based ACL is evaluated against a source address conveyed by unauthenticated early data (TCP Fast Open / QUIC 0-RTT), so an attacker can have requests processed under an identity the ACL never verified. The analog in XOXNO Lending is a check-the-wrong-identity bug: several controller guards authenticate `caller` against the `owner` field cached inside the stored `Account` struct (`account.owner`), while the protocol's own ownership invariant states that the position-NFT holder (`owner_of`) is the account owner. Because `transfer`/`approve` on the position NFT cannot notify the controller, `account.owner` goes stale the moment an NFT moves. Any controller path that authorizes via `require_owner_or_delegate`/`is_owner_or_delegate` then makes its access decision on an address that no longer owns the account — exactly the "access control keyed to an attribute established before authentication" shape of CVE-2024-45397.

### Finding Description
- `create_account_with` mints the NFT to `owner` and persists `Account { owner: owner.clone(), .. }` (contracts/controller/src/account.rs:63-70). This is the only place `account.owner` is set; nothing ever rewrites it.
- `require_account_owner` correctly re-derives ownership from the NFT (`storage::account_owner` → `Base::owner_of`) and requires it to equal the caller (account.rs:143-148). It is used for `renew_account` and delegate management (account.rs:217-231, 249-250).
- However, `is_owner_or_delegate` / `require_owner_or_delegate` compare `caller` against the *stored* `account.owner` field and the delegate list keyed by that stored owner (account.rs:115-140). These guards are reached by `load_or_create_account` under `AccountGuard::Migrate` and `AccountGuard::Multiply` (account.rs:99-110), which gate `migrate_from_blend` and `flash_position`/`multiply` on existing accounts.
- The position NFT's `transfer`/`transfer_from`/`approve` are the stock OpenZeppelin non-fungible implementation (`NonFungibleToken`/`NonFungibleEnumerable` impls in contracts/position-nft/src/contract.rs:131-173) and contain no controller callback, so a sale or gift of the NFT leaves `account.owner` pointing at the seller.

The result is a split-brain authorization: after a transfer, the new NFT owner is the legitimate owner for NFT-keyed checks, while the *old* owner still satisfies every `account.owner`-keyed guard.

### Impact Explanation
An unprivileged attacker can:
1. Supply collateral and open debt on an account, then `transfer` the position NFT to a buyer (or accomplice address).
2. Continue to satisfy `require_owner_or_delegate` as the stale `account.owner`, e.g. invoking `flash_position`/`multiply`/`migrate_from_blend` against the account the victim believes they now own, stacking further flash-minted debt against the victim's collateral and extracting the borrowed/flashed proceeds.
3. Conversely, grants/revocations of delegates made by the victim (`require_account_owner` NFT path) write delegate entries under the *new* owner's key, while `is_owner_or_delegate` reads the list under the *old* stored owner — so the victim cannot revoke pre-sale delegates either.

This is theft/freezing of user funds reachable entirely through in-scope entrypoints (`position-nft transfer`, `flash_position`, `multiply`, `migrate_from_blend`).

### Likelihood Explanation
Any secondary-market sale, OTC transfer, or wallet migration of a position NFT triggers the divergence; no privileged action, oracle manipulation, or reentrancy is required. The attacker only needs to have owned the account at mint time — a condition they fully control by front-running the sale (create account → list/sell NFT → immediately exercise stale-owner verbs in the same or a later transaction).

### Recommendation
Remove the stored `Account.owner` field from authorization decisions: derive ownership exclusively from `storage::account_owner`/`Base::owner_of` at check time (as `require_account_owner` already does), and key `get_delegates` by the resolved NFT owner rather than the persisted field. Alternatively, make the NFT non-transferable or add a controller-mediated transfer hook that rewrites `account.owner` and clears delegates.

### Proof of Concept
```
1. ATTACKER calls controller.supply(account_id=0) -> creates account A,
   NFT minted to ATTACKER; Account.owner = ATTACKER.
2. ATTACKER borrows/deposits collateral into A (optional debt for later legs).
3. ATTACKER calls position_nft.transfer(ATTACKER -> VICTIM, token_id=A).
   owner_of(A) = VICTIM, but Account.owner remains ATTACKER.
4. VICTIM (NFT holder) can renew/set delegates, but ATTACKER still calls
   controller.flash_position(caller=ATTACKER, account_id=A, ...) — 
   load_or_create_account(AccountGuard::Multiply) ->
   require_owner_or_delegate(ATTACKER, account.owner=ATTACKER) passes.
5. ATTACKER mints fee-free flash debt against A's collateral, receives the
   measured receipt via his own receiver contract, leaving VICTIM's NFT
   encumbered with the new debt; ATTACKER walks away with the proceeds.
```
The root cause is at contracts/controller/src/account.rs:64-70 (owner frozen at mint), account.rs:115-127 (`caller == account.owner` check), and contracts/position-nft/src/contract.rs:131-173 (stock transfer with no controller notification).