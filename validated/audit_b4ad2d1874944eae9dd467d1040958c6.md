### Title
Tokens transferred directly to the pool or controller are permanently frozen — no rescue path exists - (File: contracts/pool/src/lib.rs)

### Summary
Analogous to `ImmutableBundle`'s unrescuable `transferFrom` bundles, XOXNO Lending's `LiquidityPool` and controller custody tokens but expose no entrypoint — privileged or otherwise — that can return tokens sent to them outside the intended flows. The pool treats `cash` as a bookkeeping figure, not `token.balance()`; any balance above the booked cash across all `(hub, asset)` markets is unreachable excess [1](#0-0) . Every mutating entrypoint on the pool is `#[only_owner]` (the controller), and none of them is a sweep [2](#0-1) . The in-repo test for GH-17 confirms the controller likewise "holds funds no balance-delta measurement can ever claim" [3](#0-2) , and the threat model states donations "do not rewrite those books" [4](#0-3) .

### Finding Description
The pool's `supply`, `repay`, and `recapitalize` assume the controller moved exactly the declared amount in before the call and only credit `cash`; they never reconcile the surplus, and the only `token.balance()` reconciliation is the strict-equality check inside `flash_loan` [5](#0-4) . There is no `sweep_balance`, `rescue`, or equivalent on the pool's `LiquidityPoolInterface` [6](#0-5) , no corresponding controller endpoint, and no governance operation type that could invoke one (contrast `contracts/swap-aggregator`, which does have `sweep_balance` for this exact problem [7](#0-6) ).

Concretely, an unprivileged user calling `token.transfer(user, pool_address, amount)` (or to the controller address) creates a balance that no booked claim, refund, or recapitalization will ever pay out: `recapitalize` refunds only amounts exceeding the current backing shortfall of the tokens newly transferred in that call [8](#0-7) , and withdrawals/borrows only move tokens against debited `cash`. The audit test explicitly encodes this: a donation of `7 * UNIT` leaves every market's `cash` untouched and sits as permanently excess `balance` [9](#0-8) .

### Impact Explanation
Permanent freezing of funds. Tokens mistakenly sent directly to the pool or controller address — e.g., a user transferring collateral to the pool instead of calling `controller.supply`, a common wallet/UI error — can never be recovered by anyone, including governance and the owner. The funds are not merely misallocated; they are unspendable, because no code path transfers tokens out except against booked `cash`, debt, or a flash repayment check.

### Likelihood Explanation
Likelihood is moderate: direct token transfers to contract addresses are a routine user error (the exact scenario of the reference report, where `transferFrom` instead of `safeTransferFrom` bricked bundles). No attacker action is needed; the loss is self-inflicted but irreversible by design. Medium severity at most, since the victim is the sender rather than the protocol.

### Recommendation
Add an owner/governance-reachable sweep on the pool that transfers out only `token.balance(pool) - sum_of_booked_cash` (the excess across all `(hub, asset)` markets sharing the token), plus a documented recovery path for the controller's stray balances. Alternatively, document the donation-is-permanent behavior prominently, as the codebase already partially does for pool donations [10](#0-9) .

### Proof of Concept
1. Deploy standard hub; `BOB` supplies ETH so the pool holds real `cash`.
2. `user` calls `token.transfer(user, pool_addr, X)` directly — no controller involvement.
3. `get_reserves`/`get_sync_data` show `cash` unchanged while `token.balance(pool) == cash + X`.
4. No entrypoint exists to move `X` out: `withdraw`/`borrow`/`claim_revenue` are capped by `cash`, `repay`/`recapitalize` only refund the same call's inflow, `seize_positions` moves no tokens, and all pool mutators require the controller — which itself has no sweep. `X` is frozen permanently.

### Citations

**File:** contracts/pool/README.md (L61-63)
```markdown
controller's word, without verifying the transfer. `cash` is a bookkeeping
number. The only reconciliation against a real `token.balance()` is in
`flash_loan`, which checks it three times with strict equality.
```

**File:** contracts/pool/src/lib.rs (L100-252)
```rust
impl LiquidityPoolInterface for LiquidityPool {
    /// Creates a new asset market under `hub_id` with the given rate
    /// parameters. Initializes indexes at RAY (1.0) with zero cash, supply,
    /// and debt; panics with `AssetAlreadySupported` if the hub-asset pair
    /// already exists. Restricted to the owner.
    #[only_owner]
    fn create_market(env: Env, hub_id: u32, params: MarketParamsRaw) {
        ops::market::create(&env, hub_id, params);
    }

    /// Replaces the interest-rate model (curve, utilization cap, reserve
    /// factor) and flash-loan settings for a market. Accrues interest first so
    /// the old model applies through the current ledger, then writes the new
    /// model into market params. Restricted to the owner.
    #[only_owner]
    fn update_params(env: Env, hub_asset: HubAssetKey, model: InterestRateModel) {
        ops::market::replace_rate_model(&env, hub_asset, model);
    }

    /// Upgrades the contract WASM to `new_wasm_hash`, extending instance TTL
    /// first. Restricted to the owner.
    #[only_owner]
    fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        renew_instance(&env);
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(new_wasm_hash));
    }

    /// Accrues, mints scaled supply shares and credits cash per entry. The
    /// controller transfers the tokens in before this call. Owner-only.
    #[only_owner]
    fn supply(env: Env, entries: Vec<PoolSupplyEntry>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, ops::supply::apply)
    }

    /// Batch-borrows assets and transfers them to `receiver`: accrues
    /// interest, mints scaled debt, debits cash, and enforces max
    /// utilization after each mint. Restricted to the owner; returns one
    /// [`PoolPositionMutation`] per entry.
    #[only_owner]
    fn borrow(
        env: Env,
        receiver: Address,
        entries: Vec<PoolBorrowEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::borrow::apply(env, &receiver, entry)
        })
    }

    /// Burns supply shares and transfers the underlying to `receiver`.
    /// `is_liquidation` skips the max-utilization check and may withhold a
    /// protocol fee. Owner-only; `actual_amount` is gross of that fee.
    #[only_owner]
    fn withdraw(
        env: Env,
        receiver: Address,
        is_liquidation: bool,
        entries: Vec<PoolWithdrawEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::withdraw::apply(env, &receiver, is_liquidation, entry)
        })
    }

    /// Burns scaled debt up to the repay amount, credits cash with the net
    /// repay and refunds overpayment to `payer`. Owner-only.
    #[only_owner]
    fn repay(env: Env, payer: Address, actions: Vec<PoolAction>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, actions, |env, action| {
            ops::repay::apply(env, &payer, action)
        })
    }

    /// Accrues interest for each market in `hub_assets` through the current
    /// ledger time. Commits state even with no elapsed time to reserve the write
    /// footprint, and emits its market state event. Restricted to the owner.
    #[only_owner]
    fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>) {
        ops::market::accrue(&env, hub_assets);
    }

    /// Credits cash up to the market's backing shortfall
    /// (`guards::backing_shortfall`) and transfers the excess back to `payer`.
    /// The controller transfers `amount` in before this call. Restricted to
    /// the owner; returns a [`PoolAmountMutation`] with the amount applied.
    #[only_owner]
    fn recapitalize(
        env: Env,
        hub_asset: HubAssetKey,
        payer: Address,
        amount: i128,
    ) -> PoolAmountMutation {
        ops::recapitalize::apply(&env, hub_asset, payer, amount)
    }

    /// Transfers out, invokes `execute_flash_loan` on the receiver, pulls
    /// principal plus fee back via `transfer_from`, and books the fee as
    /// protocol revenue. Returns the fee. Owner-only; requires the market to
    /// allow flash loans.
    #[only_owner]
    fn flash_loan(
        env: Env,
        hub_asset: HubAssetKey,
        initiator: Address,
        receiver: Address,
        amount: i128,
        data: Bytes,
    ) -> i128 {
        ops::flash::apply(&env, hub_asset, initiator, receiver, amount, data)
    }

    /// Mints debt for `action.amount`, books the fee as protocol revenue when
    /// `charge_fee`, and sends `amount - fee` to `receiver`. Owner-only.
    #[only_owner]
    fn create_strategy(
        env: Env,
        receiver: Address,
        action: PoolAction,
        charge_fee: bool,
    ) -> PoolStrategyMutation {
        ops::strategy::apply(&env, &receiver, action, charge_fee)
    }

    /// Seizes positions during liquidation or bad-debt cleanup. Borrow-side
    /// entries socialize bad debt onto the supply index and burn the debt;
    /// deposit-side entries reclassify supply shares as protocol revenue.
    /// Restricted to the owner.
    #[only_owner]
    fn seize_positions(env: Env, entries: Vec<PoolSeizeEntry>) {
        ops::run_batch(&env, entries, |e, entry| ((), ops::seize::apply(e, entry)));
    }

    /// Nets supply against debt on one market with no cash movement, capped by
    /// the conservative overlap of floored supply and ceiled debt. Owner-only.
    #[only_owner]
    fn net_settle(env: Env, entry: PoolNetSettleEntry) -> PoolNetSettleResult {
        renew_instance(&env);
        let (result, snapshot) = ops::net_settle::apply(&env, &entry);
        events::emit_market_state(&env, snapshot);
        result
    }

    /// Burns claimable revenue shares, debits cash and pays the owner the lesser
    /// of cash and revenue's floored token value. Returns zero when nothing is
    /// claimable. Owner-only.
    ///
    /// Decrements the snapshot `revenue` field, so that field is not a
    /// cumulative counter.
    #[only_owner]
    fn claim_revenue(env: Env, hub_asset: HubAssetKey) -> PoolAmountMutation {
        ops::revenue::apply(&env, hub_asset)
    }
```

**File:** tests/test-harness/tests/controller/recipient_is_protocol_contract.rs (L1-5)
```rust
//! GH-17. A borrow or withdraw addressed to the pool or the controller
//! strands the tokens: the pool debits cash without its balance moving, and
//! the controller holds funds no balance-delta measurement can ever claim.
//! Both recipients are rejected before any transfer, with the same error the
//! flash-position receiver check uses.
```

**File:** docs/explanation/threat-model.md (L129-132)
```markdown
One token listed in several hubs shares physical pool custody even though
market books are separate. Direct donations do not rewrite those books.
Cash flash loans impose exact balance transitions and allowance repayment;
receipt-tax compatibility elsewhere does not establish flash-loan compatibility.
```

**File:** contracts/swap-aggregator/src/lib.rs (L187-202)
```rust
    /// Transfers each token's balance above its reserved fee total to `recipient`. Owner only.
    #[only_owner]
    fn sweep_balance(env: Env, recipient: Address, tokens: Vec<Address>) {
        renew_instance(&env);
        let router = env.current_contract_address();
        let n = tokens.len();
        for i in 0..n {
            // `i < n == tokens.len()`, so the index is in range by construction.
            let token = tokens.get_unchecked(i);
            let client = token::Client::new(&env, &token);
            let balance = client.balance(&router);
            let reserved = storage::reserved_fee_balance(&env, &token);
            if balance > reserved {
                client.transfer(&router, &recipient, &(balance - reserved));
            }
        }
```

**File:** tests/test-harness/tests/pool_money_flow_audit.rs (L86-96)
```rust
    // An unsolicited donation belongs to no market's cash book.
    market.token_admin.mint(&payer, &(7 * UNIT));
    token.transfer(&payer, &market.pool, &(7 * UNIT));
    let check = |supply, debt, label: &str| {
        let state = books(&t, &key, supply, debt);
        let other = books(&t, &second, secondary_supply, 0);
        assert_eq!(other.cash, 100 * UNIT);
        assert_eq!(
            token.balance(&market.pool),
            state.cash + other.cash + 7 * UNIT
        );
```

**File:** docs/reference/architecture.md (L57-61)
```markdown
The pool tracks cash in an accounting book. Supply, repayment, and
recapitalization credit the tokens actually received; direct donations do not
automatically increase booked cash. When a token delivers less than requested,
the pool books the smaller measured amount. Measurement cannot establish that an
arbitrary token is safe.
```
