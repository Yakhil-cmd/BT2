### Title
Tokens sent to the controller are permanently locked — no sweep/rescue entrypoint exists - ([File: contracts/controller/src/lib.rs])

### Summary
The lending controller can hold token balances (direct user transfers, or leftovers that pre-date a strategy's balance snapshot), but the `ControllerInterface` exposes no entrypoint that moves arbitrary tokens out of the contract. Unlike analogous strategies that ship a `withdraw()` escape hatch, every controller path that emits tokens is strictly delta-measured against a pre-call snapshot, so pre-existing balances are unrecoverable.

### Finding Description
All token-moving flows treat the controller's balance as a transient buffer measured by balance delta:

- `migrate_from_blend` snapshots controller balances before the Blend sweep and only deposits the positive delta (`deposit_withdrawn`, `contracts/controller/src/strategies/migrate_blend.rs:203-230`); the comment on `reconcile_debt_refunds` states "Pre-existing controller funds remain untouched" (`migrate_blend.rs:232-234`).
- `flash_position`, `multiply`, `swap_*` strategies similarly forward only measured receipts; nothing refunds a baseline balance.
- The full public surface (`contracts/controller/src/lib.rs:88-543`, `ControllerInterface`) plus the admin surface (`ControllerAdmin`, `lib.rs:545-837`) contains no `sweep`, `rescue`, or token-recovery function — the only token outflows are tied to supply/borrow/withdraw/repay/liquidate accounting or revenue claims, all of which require an internal ledger credit, not a raw balance.

Compare with the pool's sibling design: the swap-aggregator in this codebase ships `sweep_balance` (protected by an O(1) reserved-fee counter, see `contracts/swap-aggregator/tests/unit/sweep.rs`), and the pool itself only releases tokens against booked `cash`/shares. The controller has neither a sweep nor any booking of stray balances, so a token balance on the controller address is stranded forever, and can even distort subsequent `migrate_from_blend`/`flash_position` delta measurements (a stray balance in a debt asset means the "refund" leg is under-measured — the tokens stay locked).

### Impact Explanation
Permanent freezing of user funds: any tokens held at the controller address — via direct `token.transfer` (explicitly in-scope per the rules) or residuals left by a strategy — cannot be withdrawn by anyone, including governance/owner, since no admin entrypoint pays out tokens either.

### Likelihood Explanation
Reachable by any unprivileged address via `token.transfer(from=user, to=controller, amount>0)`. Also arises organically: Blend withdrawal rounding or interest accrued between snapshot and sweep can leave small positive residuals on the controller after `migrate_from_blend`, which `reconcile_debt_refunds`/`deposit_withdrawn` deliberately skip because they only deposit the delta above the pre-call snapshot.

### Recommendation
Add an owner- or governance-gated `sweep_balance(recipient, tokens)` entrypoint to the controller, or route stray balances through the accumulator, while preserving the delta-based measurement guarantees of strategy flows (e.g., sweeping must not be callable inside an active strategy/flash callback — reuse the existing flash guard if applicable).

### Proof of Concept
```rust
// Any user, no protocol state needed:
let token = token::Client::new(&env, &usdc);
sac_usdc.mint(&user, &1_000);
token.transfer(&user, &controller_addr, &1_000);
// token.balance(&controller_addr) == 1_000
// There is no ControllerInterface/ControllerAdmin entrypoint that moves
// these tokens out: withdraw/borrow require account supply shares or
// collateral, repay refunds only the caller's measured overpayment,
// claim_revenue only pays booked pool revenue. Funds are locked.
``` [1](#0-0) [2](#0-1)

### Citations

**File:** contracts/controller/src/lib.rs (L88-134)
```rust
#[contractimpl]
impl ControllerInterface for Controller {
    /// Supplies `assets` as collateral and returns the account id; `account_id = 0`
    /// creates an account in `spoke_id`. Third parties may only top up existing
    /// supply positions; owners and delegates may add assets.
    #[when_not_paused]
    fn supply(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        assets: Vec<(HubAssetKey, i128)>,
    ) -> u64 {
        positions::process_supply(&env, &caller, account_id, spoke_id, &assets)
    }

    /// Borrows against `account_id`'s collateral, paying `to` or the caller.
    /// Requires owner or delegate authorization and post-borrow solvency.
    #[when_not_paused]
    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) {
        positions::process_borrow(&env, &caller, account_id, &borrows, to);
    }

    /// Withdraws collateral to `to` or the caller and returns actual amounts in
    /// asset units. Zero withdraws an asset's full position. Requires owner or
    /// delegate authorization and post-withdrawal solvency.
    fn withdraw(
        env: Env,
        caller: Address,
        account_id: u64,
        withdrawals: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) -> Vec<(HubAssetKey, i128)> {
        positions::process_withdraw(&env, &caller, account_id, &withdrawals, to)
    }

    /// Repays `account_id`'s debt using measured payments from the caller.
    /// Anyone may repay; excess payments are refunded to the caller.
    fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>) {
        positions::process_repay(&env, &caller, account_id, &payments);
    }
```

**File:** contracts/controller/src/strategies/migrate_blend.rs (L202-230)
```rust
/// Deposits only positive controller receipts since the pre-withdraw snapshot.
fn deposit_withdrawn(
    env: &Env,
    account: &mut Account,
    cache: &mut Context,
    hub_id: u32,
    withdraw_assets: &Vec<Address>,
    before: &Map<Address, i128>,
) {
    let mut deposits: Vec<(HubAssetKey, i128)> = Vec::new(env);
    let controller = env.current_contract_address();
    for asset in withdraw_assets.iter() {
        let prev = before.get(asset.clone()).unwrap_or(0);

        let received = balance_delta_since(env, &asset, &controller, prev);
        if received > 0 {
            deposits.push_back((HubAssetKey { hub_id, asset }, received));
        }
    }
    if !deposits.is_empty() {
        supply::process_deposit(
            env,
            &env.current_contract_address(),
            account,
            &deposits,
            cache,
        );
    }
}
```
