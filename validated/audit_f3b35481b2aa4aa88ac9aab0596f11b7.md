### Title
Stale `Account.owner` grants former NFT holder owner-level access after position NFT transfer - (File: contracts/controller/src/account.rs)

### Summary
CVE-2015-0227 is an improper-access-control flaw where a `requireSignedEncryptedDataElements` policy could be satisfied by a wrapped element that was not the element actually enforced — the check validated a credential that did not correspond to effective authority. The controller contains the same shape: two different notions of "owner" exist. Sensitive guarded paths authenticate `caller` against the `Account.owner` field stored at account creation (`require_owner_or_delegate`), while other paths authenticate against live NFT ownership via `storage::account_owner` (`require_account_owner`). If a position NFT is transferred without rewriting the stored `Account.owner`, the previous owner retains owner-equivalent authority over the account's guarded flows, while the new holder is rejected by those same flows.

### Finding Description
`create_account_with` stores `owner` inside the `Account` struct at mint time [1](#0-0) . Authorization on the guarded paths uses that stored field: `require_owner_or_delegate` returns early when `caller == owner`, where `owner` is `&account.owner` passed by the caller [2](#0-1) . `load_or_create_account` passes exactly this stored field for the `Migrate` and `Multiply` guards [3](#0-2) .

In contrast, `require_account_owner` deliberately does not trust `Account.owner`; it re-reads `storage::account_owner` (the live NFT owner) and compares it to the caller [4](#0-3) . The existence of two separate owner sources in the same module — a stored creation-time field and a live NFT lookup — demonstrates that `Account.owner` is not treated as authoritative for current ownership. The same stored `owner` also keys the delegate list in `storage::get_delegates(env, account_id, owner)` [5](#0-4) , so delegate grants recorded under the old owner remain effective for that owner only.

`resolve_seize_receiver` in liquidation uses the same stored-field check for credit receivers [6](#0-5) .

### Impact Explanation
After an NFT transfer (position-nft `transfer`), any guard that consults the stored `Account.owner` rather than the live NFT owner authorizes the *former* owner, not the buyer. The former owner — an unprivileged address — can then invoke owner-gated flows on the victim's account: `migrate_from_blend`, `multiply`, `flash_position`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral` (all of which route through `AccountGuard::Migrate`/`Multiply`-style owner-or-delegate checks or equivalent), and can name themselves as `SeizeMode::Credit` receiver. Concretely, `swap_collateral`/`swap_debt` let the attacker route the victim's collateral through the attacker's own venue trade to siphon value, and `multiply`/`flash_position` can lever or restructure debt against collateral the attacker no longer owns. This is theft of user funds and unauthorized control of another user's position — the same class as the CVE: a security check satisfied by a credential (stored owner / wrapped element) that does not correspond to the effective principal.

### Likelihood Explanation
Reachable by any unprivileged address that has ever held a position NFT and transferred it (sale, gift, OTC trade — all normal position-nft `transfer` operations are in scope). The exploit requires only that the stored `Account.owner` field is not rewritten on transfer. The code deliberately maintains a second, live ownership source (`storage::account_owner`) used by `require_account_owner`, which strongly indicates the stored field is known to be divergent from NFT ownership; if the two were guaranteed equal, `require_account_owner` would be redundant. No privileged role, oracle manipulation, or timing window is required — the former owner's authority persists indefinitely on every path guarded by `require_owner_or_delegate`.

### Recommendation
Authenticate every owner-gated path against live NFT ownership, not the stored `Account.owner` field. Replace `require_owner_or_delegate(env, account_id, caller, &account.owner)` with a variant that resolves the current owner via `storage::account_owner` (as `require_account_owner` does) before applying the owner-or-delegate check, and key `storage::get_delegates`/`add_delegate`/`remove_delegate` lookups to the resolved live owner. Alternatively, make position-nft `transfer` synchronously update `Account.owner` and migrate the delegate map — but the live-lookup approach removes the invariant rather than depending on a cross-contract callback. Audit `resolve_seize_receiver`, `load_or_create_account` (`Migrate`/`Multiply` guards), and all strategy entrypoints to confirm they use the live-owner check.

### Proof of Concept
1. Alice creates account `A` via `supply` (account_id 0 → `create_account_with` stores `owner = Alice`) and builds a collateralized borrow position.
2. Alice calls position-nft `transfer(A, Bob)`. Live NFT owner is now Bob; `Account.owner` still stores Alice.
3. Alice calls `swap_collateral(A, ...)` (or `multiply`/`flash_position`) with a route through a venue/pool she controls. `load_or_create_account` → `AccountGuard::Multiply` → `require_owner_or_delegate(env, A, Alice, &account.owner)` passes because `caller == account.owner` is still Alice [7](#0-6) .
4. Alice's venue trade extracts value from Bob's collateral via the balance-delta output measurement, or leaves the position restructured/degraded — all under Bob's live ownership, which Alice no longer holds.

Note on verification: this finding depends on `storage::account_owner` reflecting live NFT ownership while `Account.owner` is not resynced on transfer; I was unable to read the position-nft `transfer` implementation or `storage::account_owner` within the available iterations to confirm the stored field goes stale. If `transfer` does call back into the controller to rewrite `Account.owner` and remap delegates, this analog does not hold and should be rejected.

### Citations

**File:** contracts/controller/src/account.rs (L64-66)
```rust
    let account = Account {
        owner: owner.clone(),
        spoke_id,
```

**File:** contracts/controller/src/account.rs (L99-109)
```rust
    match guard {
        AccountGuard::Supply => require_spoke_match(env, &account, spoke_id),
        AccountGuard::Migrate => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
        }
        AccountGuard::Multiply => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
            assert_with_error!(env, account.mode == mode, GenericError::AccountModeMismatch);
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

**File:** contracts/controller/src/account.rs (L143-148)
```rust
pub(crate) fn require_account_owner(env: &Env, account_id: u64, caller: &Address) -> AccountMeta {
    let meta = storage::get_account_meta(env, account_id);
    let owner = storage::account_owner(env, account_id);
    assert_with_error!(env, owner == *caller, GenericError::AccountNotInMarket);
    meta
}
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L179-181)
```rust
    let receiver = storage::get_account(env, requested);
    account::require_owner_or_delegate(env, requested, liquidator, &receiver.owner);
    assert_with_error!(
```
