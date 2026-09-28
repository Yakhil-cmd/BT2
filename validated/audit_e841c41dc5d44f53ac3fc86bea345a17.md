### Title
Direct token transfers to the LiquidityPool or Controller are permanently locked — no credit, no recovery path - (File: contracts/pool/src/lib.rs)

### Summary
Analogous to unguarded `receive()` functions locking Ether, XOXNO Lending's pool and controller contracts accept arbitrary SAC token transfers from any address but have no entrypoint that credits, sweeps, or refunds them. Because cash is an accounting book separate from the token balance (`contracts/pool/src/lib.rs:34-35`), a direct `token.transfer` to the pool raises custody without raising any market's `cash`, so no withdraw, borrow, revenue claim, or refund path can ever release it.

### Finding Description
Every pool mutation that moves tokens is `#[only_owner]` (the controller), and each is bounded by the internal books:

- `withdraw` / `borrow` pay out only against the market's `cash` book and its solvency guards [1](#0-0) 
- `claim_revenue` pays `min(cash, revenue)` — donated tokens raise neither [2](#0-1) 
- `recapitalize` credits only up to the market's backing shortfall and transfers the excess back to `payer`, so it cannot be abused to credit a donation [3](#0-2) 

The codebase itself documents that donations are orphaned: the threat model states "Direct donations do not rewrite those books" [4](#0-3) , and the money-flow test asserts a 7-unit direct transfer stays outside every market's cash book permanently [5](#0-4) .

The controller has the same shape: `test_migrate_refund_ignores_preexisting_controller_balance` proves tokens already sitting on the controller are never used, refunded, or swept — they just remain [6](#0-5) . Borrow/withdraw explicitly reject the pool/controller as `receiver` *because* funds sent there are stranded ("the controller holds funds no balance-delta measurement can ever claim") [7](#0-6) .

Unlike the swap-aggregator, which exposes `sweep_balance` for exactly this situation [8](#0-7) , neither the pool nor the controller exposes any sweep/recovery entrypoint.

### Impact Explanation
Permanent freezing of funds. Any tokens (including native XLM SAC) an address transfers directly to the pool or controller become unspendable surplus custody: they are not credited to any position, cannot be withdrawn by anyone, cannot be claimed as revenue, and can only be recovered through a privileged contract upgrade — which is out of scope. The pool balance permanently exceeds total booked cash, so even a full wind-down leaves the donation behind.

### Likelihood Explanation
Reachable by any unprivileged address via a plain `token.transfer(from=user, to=pool_or_controller, amount)` — no contract interaction needed beyond the token's own interface. Likelihood depends on users/frontends mistakenly funding the contract directly (e.g., to "supply" or top up a margin position), which is exactly the scenario the original report describes. This is a user-error-driven loss, hence Medium rather than High — it requires the victim to self-inflict the transfer, but nothing warns or blocks it.

### Recommendation
Mirror the swap-aggregator's mitigation:

- Add an owner-gated `sweep_balance`-style entrypoint on the pool that transfers out `balance - total_booked_cash_across_all_markets_on_that_asset`, and an equivalent recovery on the controller; or
- Document the unrecoverable-donation behavior in the contract interface and ensure frontends never produce raw `transfer` calls to these addresses.

A restrictive alternative matching the original report's recommendation is not available on Soroban (SAC transfers to a contract address cannot be rejected), so a book-aware sweep is the practical fix.

### Proof of Concept
1. Deploy pool + controller with a USDC market; supplier calls `controller.supply`, pool books `cash = deposit`, `token.balance(pool) == deposit`.
2. Any address calls `token.transfer(user -> pool, X)` (or `-> controller`). No auth from the protocol is needed.
3. `pool.get_reserves(key)` still returns `deposit`; `token.balance(pool) == deposit + X`.
4. No reachable entrypoint releases `X`: `withdraw`/`borrow` are bounded by `cash`, `claim_revenue` by `min(cash, revenue)`, `recapitalize` refunds its own excess, and no sweep exists. `X` is locked permanently.

### Citations

**File:** contracts/pool/src/lib.rs (L150-163)
```rust
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
```

**File:** contracts/pool/src/lib.rs (L182-194)
```rust
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
```

**File:** contracts/pool/src/lib.rs (L243-252)
```rust
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

**File:** docs/explanation/threat-model.md (L129-132)
```markdown
One token listed in several hubs shares physical pool custody even though
market books are separate. Direct donations do not rewrite those books.
Cash flash loans impose exact balance transitions and allowance repayment;
receipt-tax compatibility elsewhere does not establish flash-loan compatibility.
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

**File:** tests/test-harness/tests/strategy/migrate_blend.rs (L529-535)
```rust
    let controller_eth = t.env.as_contract(&t.controller, || {
        soroban_sdk::token::Client::new(&t.env, &eth).balance(&t.controller)
    });
    assert_eq!(
        controller_eth, stuck,
        "pre-existing controller ETH must remain (not used as refund or swept)"
    );
```

**File:** tests/test-harness/tests/controller/recipient_is_protocol_contract.rs (L1-5)
```rust
//! GH-17. A borrow or withdraw addressed to the pool or the controller
//! strands the tokens: the pool debits cash without its balance moving, and
//! the controller holds funds no balance-delta measurement can ever claim.
//! Both recipients are rejected before any transfer, with the same error the
//! flash-position receiver check uses.
```

**File:** contracts/swap-aggregator/tests/unit/sweep.rs (L12-36)
```rust
#[test]
fn sweep_balance_recovers_stray_tokens_to_recipient() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let router_addr = env.register(Router, (admin.clone(),));
    let asset_admin = Address::generate(&env);
    let (stray_token, sac_stray) = new_asset(&env, &asset_admin);
    let (untouched_token, sac_untouched) = new_asset(&env, &asset_admin);
    let recipient = Address::generate(&env);

    sac_stray.mint(&router_addr, &1_234);
    sac_untouched.mint(&router_addr, &500);

    RouterClient::new(&env, &router_addr)
        .sweep_balance(&recipient, &vec![&env, stray_token.clone()]);

    assert_eq!(
        token::Client::new(&env, &stray_token).balance(&router_addr),
        0
    );
    assert_eq!(
        token::Client::new(&env, &stray_token).balance(&recipient),
        1_234
    );
```
