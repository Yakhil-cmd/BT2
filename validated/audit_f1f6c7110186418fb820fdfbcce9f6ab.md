### Title
Unfunded `recapitalize` inflates pool cash and permanently blocks withdrawals - ([File: contracts/pool/src/ops/recapitalize.rs])

### Summary
`recapitalize` trusts its `amount` argument and credits `cash` up to the accounting shortfall, while separately refunding `amount - applied`; it does not verify that the pool actually received `amount` tokens first. Because withdrawals validate only the tracked `cash` balance before performing a real token transfer, an unfunded recapitalization can leave the market's cash book greater than its token custody. Subsequent suppliers pass the pool's liquidity guard but revert inside the token transfer, freezing their underlying deposits.

### Finding Description
The pool's recapitalization path computes `applied = amount.min(backing_shortfall)` and `refund = amount - applied`, then credits only `applied` to the market's `cash` book and commits that state. [1](#0-0)  After accounting commits, `apply` transfers the refund to the payer. [2](#0-1)  There is no balance-delta measurement in this operation proving that the pool received `amount` before crediting and refunding it; the code only contains the controller-side convention that tokens are transferred before the call. [3](#0-2) 

The withdrawal path checks `cash >= net_transfer` and debits that bookkeeping amount before `transfer_out` invokes the token contract. [4](#0-3)  `transfer_out` does not reconcile accounting cash with `token.balance(pool)`; it merely calls `token.transfer` after the accounting state has already been updated in the same transaction. [5](#0-4)  Thus, if accounting cash has been credited without matching custody, a withdrawer's request passes the internal reserve check and then fails at the token layer.

The repository already contains a regression-style demonstration of this state: an unfunded recapitalization drains actual custody to the payer while leaving `cash >= deposit`; the later withdraw clears the pool liquidity and solvency guards and fails with the token contract's insufficient-balance error. [6](#0-5) 

### Impact Explanation
An unprivileged attacker can use the public controller `recapitalize` route to create or exploit a market whose `cash` ledger overstates real token custody. Suppliers' withdrawals then remain blocked even though their supply positions and market accounting say liquidity exists. This is permanent freezing of user funds unless an external actor replenishes the pool, and the same inflated `cash` value can also make a physically insolvent market appear solvent to other accounting paths.

The impact is stronger than a merely skipped ancillary payment: the promised principal withdrawal itself cannot execute because `transfer_out` cannot pay what the overstated `cash` book claims is available. [7](#0-6) 

### Likelihood Explanation
The attacker only needs permissionless access to the controller's `recapitalize` flow and a market whose bookkeeping permits a nonzero applied amount or refund. The vulnerable ordering is deterministic: `accounting` commits credited cash before `apply` refunds unused input, and neither function compares the pool's token balance before and after the recapitalization. [8](#0-7)  Once custody is below the committed `cash`, every withdrawal whose payout exceeds real custody follows the same path: internal `require_reserves` succeeds because it reads the inflated book, then the token transfer reverts because custody is insufficient. [9](#0-8) 

The in-repo test demonstrates this sequence with ordinary market state: a supplier deposits, custody is removed by an unfunded refund, `cash` still reports at least the deposit, and a full withdraw fails with token balance error rather than a pool liquidity error. [10](#0-9) 

### Recommendation
Measure the pool's actual receipt of recapitalization funds with a balance delta, exactly as other controller payment paths do, before allowing the pool to credit `cash`. The pool should either:

- require `received >= applied` before committing the accounting update, or
- use `received` rather than the caller-declared `amount` as the input to `applied = min(received, backing_shortfall)` and compute `refund` from the actual received amount.

If keeping inbound funding in the controller, perform `balance_before`, inbound transfer, and `balance_after - balance_before` measurement in the same transaction and pass the measured value to the pool. Do not refund more than `received`, and do not credit more `cash` than `received - refund`. An additional invariant check that committed `cash` does not exceed actual pool custody for the relevant payout leg would prevent withdrawal requests from passing `require_reserves` only to fail in the token contract.

### Proof of Concept
1. A supplier calls controller `supply`, transferring `10_000_000_000` asset units into the pool and receiving a supply position.
2. An unprivileged caller invokes controller `recapitalize(hub_asset, amount = pool_token_balance)` without the pool retaining matching funds.
3. `pool::ops::recapitalize::accounting` computes the applied amount from the book-based `backing_shortfall`, credits `cash`, commits state, and returns a refund. [11](#0-10) 
4. `apply` transfers the refund to the payer, draining the pool's actual token balance while the committed `cash` book still reports liquidity. [12](#0-11) 
5. The supplier calls controller `withdraw(account_id, [(hub_asset, 0)], to)` where zero means withdraw-all. [13](#0-12) 
6. Pool withdrawal calls `require_reserves(net_transfer)`, which succeeds because it compares the payout to the inflated `cash` value rather than to `token.balance(pool)`. [14](#0-13) 
7. `transfer_out` calls the token contract, which reverts for insufficient pool balance; the supplier receives nothing and retains the position after transaction rollback. [15](#0-14) 

The repository's `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` encodes this same sequence and asserts that the withdraw fails specifically inside the SAC transfer with balance error `10`, not because the pool's own liquidity or solvency guards rejected it. [16](#0-15)

### Citations

**File:** contracts/pool/src/ops/recapitalize.rs (L1-4)
```rust
//! Recapitalization: injects cash to cover a market backing shortfall.
//!
//! Only the shortfall amount is applied; any excess is refunded to the payer.
//! The controller transfers `amount` into the pool before this call.
```

**File:** contracts/pool/src/ops/recapitalize.rs (L26-66)
```rust
pub(crate) fn apply(
    env: &Env,
    hub_asset: HubAssetKey,
    payer: Address,
    amount: i128,
) -> PoolAmountMutation {
    let outcome = accounting(env, hub_asset, amount);

    outcome.cache.transfer_out(&payer, outcome.refund);

    events::emit_market_state(env, outcome.cache.snapshot());
    outcome.mutation
}

/// Sizes and books the cash injection without transferring tokens.
///
/// Credits `min(amount, backing_shortfall)` to cash and commits. `refund` is
/// `amount - applied`.
pub(crate) fn accounting(
    env: &Env,
    hub_asset: HubAssetKey,
    amount: i128,
) -> RecapitalizationOutcome {
    require_nonneg_amount(env, amount);
    let mut cache = ops::renewed_market(env, &hub_asset);

    let applied = amount.min(guards::backing_shortfall(&cache));
    let refund = amount
        .checked_sub(applied)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    cache.credit_cash(applied);
    cache.commit();

    RecapitalizationOutcome {
        cache,
        mutation: PoolAmountMutation {
            actual_amount: applied,
        },
        refund,
    }
```

**File:** contracts/pool/src/ops/withdraw.rs (L76-81)
```rust
    // A footprint-only close must not add a utilization gate to same-market
    // net settlement: it burns no shares and moves no cash.
    let empty_close = position.raw() == 0 && entry.action.amount == i128::MAX;
    gate_and_debit(env, &mut cache, net_transfer, is_liquidation || empty_close);

    let snapshot = cache.commit();
```

**File:** contracts/pool/src/ops/withdraw.rs (L109-119)
```rust
/// Enforces reserve, utilization, and solvency guards, then debits cash for
/// the net transfer. Liquidations and footprint-only closes skip utilization.
fn gate_and_debit(env: &Env, cache: &mut Cache, net_transfer: i128, skip_utilization_check: bool) {
    cache.require_reserves(net_transfer);

    if !skip_utilization_check {
        guards::require_utilization_below_max(env, cache);
    }
    guards::require_supply_for_debt(env, cache);
    cache.debit_cash(net_transfer);
}
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

**File:** contracts/pool/src/cache/cash.rs (L43-53)
```rust
    /// Transfers `amount` of the market asset from the pool to `recipient`.
    ///
    /// Rejects negative amounts; zero is a no-op. Does not adjust accounting cash.
    pub(crate) fn transfer_out(&self, recipient: &Address, amount: i128) {
        require_nonneg_amount(&self.env, amount);
        if amount == 0 {
            return;
        }
        let tok = token::Client::new(&self.env, &self.params.asset_id);
        tok.transfer(&self.env.current_contract_address(), recipient, &amount);
    }
```

**File:** contracts/pool/tests/flows.rs (L3405-3483)
```rust
/// reads the book, not the balance, so it admits exits that then fail inside
/// the SAC transfer. The market reports itself solvent and cannot pay.
#[test]
fn test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody() {
    let t = TestSetup::new();
    let token = token::Client::new(&t.env, &t.asset);
    let token_admin = token::StellarAssetClient::new(&t.env, &t.asset);
    let payer = Address::generate(&t.env);
    let receiver = Address::generate(&t.env);

    // A legitimate supplier, with custody moved in as the controller would.
    let deposit = 10_000_000_000i128;
    token_admin.mint(&t.pool, &deposit);
    let supplied = t
        .client()
        .supply(&t.sup(0, deposit))
        .get_unchecked(0)
        .position
        .scaled_amount;
    assert_eq!(
        t.state_snapshot().cash,
        token.balance(&t.pool),
        "fixture guard: book and custody must still agree after the deposit"
    );

    // Drain every token via an unfunded refund.
    let custody = token.balance(&t.pool);
    t.client().recapitalize(&hub(&t.asset), &payer, &custody);
    assert_eq!(token.balance(&t.pool), 0, "custody is gone");

    let book = t.state_snapshot().cash;
    assert!(
        book >= deposit,
        "the book still claims more than the supplier's deposit: {book}"
    );

    // The supplier's exit clears the pool's own liquidity guard -- the book
    // says the cash is there -- and then fails in the token transfer.
    let outcome = t
        .client()
        .try_withdraw(&receiver, &false, &t.wdr(supplied, i128::MAX, 0));
    assert!(
        outcome.is_err(),
        "the withdraw cannot be paid, so it must fail"
    );
    // The failure must come from custody, not from a pool guard. The SAC
    // reports insufficient balance as its own contract error `BalanceError = 10`.
    // The asserts check that exact code and that neither pool liquidity guard
    // fired: `require_reserves` read the book and let the exit through.
    const SAC_BALANCE_ERROR: u32 = 10;
    match outcome {
        Err(Ok(err)) => {
            assert_ne!(
                err,
                Error::from_contract_error(CollateralError::InsufficientLiquidity as u32),
                "the pool's own liquidity guard must NOT be what stopped this -- \
                 it reads the cash book, which still shows the funds"
            );
            assert_ne!(
                err,
                Error::from_contract_error(CollateralError::PoolInsolvent as u32),
                "the pool's solvency guard must NOT be what stopped this either"
            );
            assert_eq!(
                err,
                Error::from_contract_error(SAC_BALANCE_ERROR),
                "the exit must fail inside the SAC transfer for want of custody"
            );
        }
        Err(Err(host_abort)) => panic!("expected a SAC contract error, got {host_abort:?}"),
        Ok(_) => unreachable!("asserted is_err above"),
    }
    assert_eq!(token.balance(&receiver), 0, "the supplier received nothing");
    assert_eq!(
        t.state_snapshot().cash,
        book,
        "the failed exit rolled back, so the book still overstates custody"
    );
}
```

**File:** contracts/controller/src/positions/supply.rs (L180-199)
```rust
    let mut entries: Vec<PoolWithdrawEntry> = Vec::new(env);
    for (hub_asset, amount) in aggregated.iter() {
        enforce_spoke_asset_flags(
            env,
            cache,
            account.spoke_id,
            &hub_asset,
            FreezePolicy::AllowOnExit,
        );
        let position = get_supply_position_or_panic(env, account, &hub_asset);
        let requested = if amount == 0 {
            WITHDRAW_ALL_SENTINEL
        } else {
            amount
        };
        entries.push_back(PoolWithdrawEntry {
            action: make_pool_action(&position, requested, hub_asset.clone()),
            protocol_fee: 0,
        });
    }
```
