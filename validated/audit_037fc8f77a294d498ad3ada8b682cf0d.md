### Title
Stale `account.owner` lets the previous NFT holder retain full spending authority after a position transfer - (File: contracts/controller/src/account.rs)

### Summary
The Grafana advisory (CVE-2025-3260) is an authorization-context bug: the permission check reads the wrong scope, so authenticated users act on resources their role does not cover. The controller has the same shape. `is_owner_or_delegate` / `require_owner_or_delegate` authorize `borrow`, `withdraw`, `multiply`, `flash_position`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, and `migrate_from_blend` by comparing the caller against `account.owner` — a field written once at account creation in `create_account_with` and never resynchronized from the position NFT. After the NFT is transferred, the previous holder still passes `caller == owner`, while the new NFT holder is rejected. The prior owner can therefore drain every position the NFT buyer just acquired.

### Finding Description
`Account.owner` is set at mint time in `create_account_with` (`account.rs:64-70`) and there is no code path that rewrites it — no `account.owner = ...` assignment exists anywhere under `contracts/controller/src`. Ownership after transfer lives only in the NFT contract, which `require_account_owner` correctly consults via `storage::account_owner(env, account_id)` (`account.rs:143-148`) for the owner-only paths (`add_delegate`, `remove_delegate`, `renew_account`).

But every spending path goes through `require_owner_or_delegate(env, account_id, caller, &account.owner)` (`account.rs:130-140`), whose first check is `caller == owner` against the stale stored field (`account.rs:121-123`). This is reachable from:

- `borrow` / `withdraw` via `positions/debt.rs` / `positions/supply.rs`
- `multiply`, `flash_position` via `load_or_create_account` guards `Migrate`/`Multiply` (`account.rs:101-109`)
- `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `migrate_from_blend`

The documented invariant INV-AUTH-02 even encodes the consequence: a delegate grant "is inactive under another owner but can reactivate if the NFT returns" — it is keyed to the stored `owner` (`account.rs:126`), so when the NFT returns to the original holder, the stale `account.owner` coincides again and the old grant reactivates without a fresh `add_delegate`. The same staleness means the ex-owner personally retains authority the whole time the NFT is held by anyone else.

Two harmful flows for a single unprivileged address:

1. Sell/transfer an account NFT carrying collateral (or a whole leveraged position), then call `withdraw(caller = old_owner, account_id, all collateral legs, to = attacker)` — `require_owner_or_delegate` passes because `caller == account.owner` (stale), and collateral leaves to the attacker.
2. Sell the NFT, then `borrow` against the buyer's collateral to `to`, leaving the new owner holding a debt-encumbered account; optionally `liquidate`/`clean_bad_debt` afterward.

The mirror image also bites the legitimate new owner: `borrow`/`withdraw` from the NFT buyer fails (`caller != account.owner`, no delegate keyed to them), so control and custody are decoupled — the person the NFT says owns the account cannot operate it without a delegate grant that only `require_account_owner` (which reads the live NFT owner) lets them create for themselves.

### Impact Explanation
Theft of user funds. Any account NFT that changes hands — sale, OTC trade, transfer to a vault/smart wallet, compromise recovery — leaves the former holder able to withdraw all collateral and borrow the account into insolvency, settling to the attacker's `to` address. The new owner cannot stop it: they cannot revoke delegates they never granted, and their own spending calls revert. Because the delegate list also reactivates on NFT return (INV-AUTH-02), a stale manager additionally regains authority with no fresh consent. Impact maps to "theft of user funds" on every transferred account; severity Critical–High given `borrow`/`withdraw` cover the entire position value.

### Likelihood Explanation
The trigger is a single `position-nft::transfer`/`transfer_from`, both stock OpenZeppelin entrypoints callable by any NFT holder (`position-nft` classified `caller-auth`, INV-AUTH-02). No price move, no HF condition, no privileged role is needed — the attacker's auth is exactly what the check accepts. The only prerequisite is that the victim obtained the account NFT by transfer rather than by `account_id = 0` creation, which is the normal path for any secondary-market or wallet-rotation use of a transferable position NFT.

### Recommendation
Resynchronize authority to the live NFT owner on every authorization decision:

- In `is_owner_or_delegate` (`account.rs:115-127`), replace `caller == owner` with `caller == storage::account_owner(env, account_id)` (or load the account with an already-synced owner), and key `get_delegates` by the current NFT owner rather than the stale `account.owner` — this also closes the reactivation window described in INV-AUTH-02.
- Alternatively, update `account.owner` on detection of an NFT transfer (e.g., a `sync_owner` step inside `storage::get_account`), and clear delegate entries on owner change so a returning NFT cannot resurrect a dormant grant.
- Converge on one source of truth: today `require_account_owner` reads the NFT while `require_owner_or_delegate` reads the struct — both should read `storage::account_owner`.

### Proof of Concept
Conceptual Soroban test (test-harness style):

```rust
// 1. Alice creates and funds an account.
let acct = t.create_spoke_account(ALICE, SPOKE);
t.supply_to(ALICE, acct, "USDC", 10_000.0);

// 2. Alice transfers the position NFT to Bob (a sale).
t.nft_client().transfer(&ALICE, &BOB, &acct);

// 3. Bob is now NFT owner — but cannot withdraw: caller != stale account.owner.
assert_contract_error(
    t.try_withdraw(BOB, acct, "USDC", 1.0, None).map(|_| ()),
    errors::NOT_AUTHORIZED,
);

// 4. Alice — no longer the owner — still passes require_owner_or_delegate
//    because caller == account.owner (stale) and drains all collateral.
t.try_withdraw(ALICE, acct, "USDC", 10_000.0, Some(ATTACKER)).unwrap();
// Bob's NFT now fronts an empty account; the funds sit at ATTACKER.
```

Root-cause lines: `Account { owner: owner.clone(), .. }` written once at `account.rs:64-70`; the stale comparison `caller == owner` at `account.rs:121-123`; the live-owner read that bypasses it at `account.rs:144-146`.

Confidence note: `contracts/controller/src/storage/account.rs` (`get_account`, `account_owner`) was not fully read in this pass, so the possibility that `get_account` rewrites `account.owner` on load cannot be fully excluded — but the existence of a distinct `storage::account_owner` NFT read inside `require_account_owner` and the documented stale-grant reactivation in INV-AUTH-02 both indicate `account.owner` is stored state that diverges from NFT ownership; if it were synced, neither would be needed.