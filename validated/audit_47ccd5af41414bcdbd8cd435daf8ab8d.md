### Title
A user can permanently lose funds sent via `repay`/`supply` because the target `account_id` is never validated against the caller's intent - (File: contracts/controller/src/positions/debt.rs)

### Summary
`Controller::repay` and `Controller::supply` accept a caller-provided `account_id` and immediately pull tokens from the caller, crediting whatever account that id resolves to. Neither entrypoint checks that the caller owns the account, that the caller intends to pay a foreign account, or any confirmation parameter. A single-digit typo in `account_id` sends real tokens to a stranger's position with no recovery path — the same bug class as Footium's unvalidated `makePayment` message.

### Finding Description
`process_repay` authenticates only `caller` and then loads `account_id` directly:

- `contracts/controller/src/positions/debt.rs:69-91` — `require_authorized_caller(env, caller)` auths the payer; `storage::get_account_borrow_only(env, account_id)` loads the *target*; `settle_repay` pulls the caller's tokens via `transfer_amount_measured` and applies them to that account's debt. No ownership or intent check links `caller` to `account_id`.
- `contracts/controller/src/positions/supply.rs:40-97` — `process_supply` similarly credits `account_id`; `require_third_party_existing_supply` only restricts *which assets* a third party may top up, never *which account*. If the typo'd `account_id` already holds the supplied hub asset, the transfer succeeds and mints supply shares to the victim-of-typo's account.
- Permissionless repay/top-up is an intended feature (docs/`invariants.md` INV-AUTH-03, `scripts/permissionless_entrypoints.txt:69-70`), but nothing in the design requires accepting an arbitrary wrong target silently: the contract cannot distinguish "generous third party" from "user typo", and the credited funds are owned by the foreign account from the moment the call commits.

The repaid debt or supplied collateral is irreversible: only the foreign account's owner (or its delegate) can `withdraw` the donated supply, and a repaid debt simply lowers a stranger's liabilities. There is no reclaim entrypoint.

### Impact Explanation
The caller's tokens are permanently transferred to an account they do not control. For `repay`, the payer's tokens extinguish someone else's debt — a pure gift. For `supply`, the minted supply shares belong to the foreign account's NFT owner. This is a permanent loss of user funds reachable by any unprivileged address through a routine entrypoint, matching the source report's "user loses their payment" impact.

### Likelihood Explanation
Requires a user error (mistyped `account_id` or integrating contract passing a stale id), so it is not exploitable at will — consistent with Medium. However, `u64` account ids are sequential and dense: almost any small typo resolves to an existing, valid account rather than reverting, so the failure mode silently succeeds instead of reverting. Integrating contracts that repay on behalf of users (a documented pattern — `abi.md` describes forwarding `amount - repaid` refunds) amplify the surface.

### Recommendation
Add an opt-in guard so mistaken targets revert instead of silently absorbing funds, e.g. an `expected_owner: Option<Address>` parameter on `repay`/`supply` that, when provided, must equal the resolved account's NFT owner; or a `recipient_confirmed: bool`/`expected_account_owner` check. At minimum, revert when `caller` is neither owner nor delegate *and* the supplied `account_id`'s owner has not opted into third-party payments.

### Proof of Concept
1. Alice owns `account_id = 12` with a USDC debt; Bob owns `account_id = 13` also with a USDC debt (any account whose id is near Alice's works).
2. Alice intends `repay(caller=alice, account_id=12, payments=[(USDC, 1000e7)])` but submits `account_id=13`.
3. `process_repay` auths Alice, loads account 13, pulls 1000 USDC from Alice via `transfer_amount_measured`, and burns Bob's debt shares. Alice's debt is untouched; her 1000 USDC is unrecoverable.
4. Same flow for `supply`: `supply(caller=alice, account_id=13, spoke_id=0_mismatch aside, assets=[(USDC, x)])` succeeds whenever account 13 already holds a USDC supply position, crediting Bob's account with Alice's tokens.