### Title
Tokens transferred directly to the LiquidityPool are permanently locked — cash accounting ignores the real token balance and no sweep exists — ([File: contracts/pool/src/lib.rs])

### Summary
The `LiquidityPool` contract holds user funds for every `(hub_id, token)` market, but its solvency, withdrawal, borrow, and recapitalization logic is driven entirely by an internal `cash` accounting book, not by the contract's actual token balance. Any tokens transferred directly to the pool address — either a market asset or any unrelated token — are invisible to all accounting paths and there is no sweep or rescue entrypoint to recover them. Unlike the swap-aggregator, which exposes an owner-only `sweep_balance`, the pool exposes no equivalent.

### Finding Description
The pool's documentation states the design explicitly: "Cash is an accounting book, separate from the token balance" [1](#0-0) . `credit_cash`/`debit_cash` are the only mutators of that book, and they are invoked solely through the `#[only_owner]` (controller-gated) entrypoints [2](#0-1) .

Consequences:

- A direct `token.transfer(from, pool, amount)` on a market asset raises the real balance but not `cash`. Withdrawals and borrows are bounded by `require_reserves(amount)` against `cash` [3](#0-2) , so the donated amount can never leave the contract.
- A direct transfer of any non-market token is even more clearly locked: no entrypoint references that token at all.
- `recapitalize` does not salvage stray tokens either. It applies `min(amount, backing_shortfall)` where the shortfall is computed from `cash + debt` vs. supply claims — the real balance is never consulted — and refunds the excess to the payer [4](#0-3) [5](#0-4) . So even when the pool is underbacked, stray tokens already sitting in the contract cannot be absorbed; a recapitalizer must send new tokens on top.
- Contrast with `contracts/swap-aggregator/src/lib.rs:189` `sweep_balance`, which exists precisely because the authors recognized stray token risk [6](#0-5) . The pool, which custodies far more value, lacks the same mechanism.

Every mutator on the pool is `#[only_owner]`, and the owner is the controller; there is no `sweep`, `rescue`, or `skim` path in either contract (grep for `sweep|rescue|recover|stray` over `contracts/pool` and `contracts/controller` returns no production-code matches).

### Impact Explanation
Permanent freezing of funds. Any tokens — market assets or arbitrary ERC20/SAC assets — sent directly to the pool contract are unrecoverable by anyone, including governance. For market assets, the tokens remain counted in the contract's real balance but are excluded from `cash`, so they can neither be withdrawn by suppliers nor absorbed via `recapitalize`; they are dead weight that can also mask undercollateralization at the token-balance layer while accounting shows a shortfall.

### Likelihood Explanation
Medium-low likelihood, real-world plausible: users routinely send tokens to contract addresses by mistake, and front-ends or integrations may transfer to the pool instead of calling `supply` through the controller. The flash-loan path also pulls repayment via `transfer_from`, and any overpayment sent directly to the pool (rather than routed through the repay call) is lost the same way. No unprivileged attacker can profit, but the loss is permanent once it happens.

### Recommendation
Add an owner-only (controller-gated) `sweep`/`skim` entrypoint to `LiquidityPool` that, for each token, transfers out `balance - expected_backing`. For market assets, `expected_backing` should be `cash` (the accounting book); for non-market tokens it is zero. Alternatively, have `recapitalize` measure the real token balance and credit `cash` up to the shortfall from pre-existing stray funds before pulling new tokens from the payer.

### Proof of Concept
1. Controller creates market `(hub_id=1, USDC)`; users supply so `cash = 1_000_000` and the pool's real USDC balance is `1_000_000`.
2. Any address calls `USDC.transfer(victim, pool, 50_000)` directly. Real balance: `1_050_000`; `cash` still `1_000_000`.
3. Attempt all exits: `withdraw`/`borrow` panic at `require_reserves` beyond `cash`; `claim_revenue` pays only `min(cash, revenue)`; `recapitalize` computes shortfall from `cash` alone and refunds excess. No entrypoint can move the `50_000`.
4. Repeat with an unrelated token XYZ sent to the pool — there is not even an accounting reference to it. The funds are locked permanently; only a WASM `upgrade` adding a sweep could recover them.

### Citations

**File:** contracts/pool/src/lib.rs (L34-36)
```rust
//! - Cash is an accounting book, separate from the token balance. A flash loan
//!   checks the token balance after payout, after the callback and after
//!   repayment.
```

**File:** contracts/pool/src/cache/cash.rs (L14-21)
```rust
    /// Panics if cash reserves are below `amount`.
    pub(crate) fn require_reserves(&self, amount: i128) {
        assert_with_error!(
            self.env,
            self.cash >= amount,
            CollateralError::InsufficientLiquidity
        );
    }
```

**File:** contracts/pool/src/cache/cash.rs (L23-41)
```rust
    /// Increases accounting cash by `amount`. Rejects negative amounts and overflow.
    pub(crate) fn credit_cash(&mut self, amount: i128) {
        require_nonneg_amount(&self.env, amount);
        self.cash = self
            .cash
            .checked_add(amount)
            .unwrap_or_else(|| panic_with_error!(&self.env, GenericError::MathOverflow));
    }

    /// Decreases accounting cash by `amount`. Rejects negative amounts or
    /// insufficient reserves.
    pub(crate) fn debit_cash(&mut self, amount: i128) {
        require_nonneg_amount(&self.env, amount);
        self.require_reserves(amount);
        self.cash = self
            .cash
            .checked_sub(amount)
            .unwrap_or_else(|| panic_with_error!(&self.env, GenericError::MathOverflow));
    }
```

**File:** contracts/pool/src/ops/recapitalize.rs (L50-58)
```rust
    let mut cache = ops::renewed_market(env, &hub_asset);

    let applied = amount.min(guards::backing_shortfall(&cache));
    let refund = amount
        .checked_sub(applied)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    cache.credit_cash(applied);
    cache.commit();
```

**File:** contracts/pool/src/guards.rs (L60-66)
```rust
/// Asset units by which supplier claims exceed cash + debt (0 if solvent).
pub(crate) fn backing_shortfall(cache: &Cache) -> i128 {
    let supplied_claim = cache.unscale_supply_floor(cache.supplied());
    let outstanding_debt = cache.unscale_borrow_ceil(cache.borrowed());
    let backing = cache.cash().saturating_add(outstanding_debt);
    supplied_claim.saturating_sub(backing).max(0)
}
```

**File:** contracts/swap-aggregator/src/lib.rs (L187-203)
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
    }
```
