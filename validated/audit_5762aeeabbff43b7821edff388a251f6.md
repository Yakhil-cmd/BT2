### Title
Missing min-out slippage protection on `withdraw()` lets a permissionless bad-debt write-down sandwich a supplier's exit - (File: contracts/controller/src/lib.rs)

### Summary
`Controller::withdraw` (and `supply`, `repay`) accept only requested token amounts — there is no `min_amount_out`/`max_shares_burned` parameter. The share exchange rate (`supply_index`) is not monotone: any unprivileged address can call `clean_bad_debt` or `liquidate`, which routes through `pool::ops::seize::apply` → `interest::apply_bad_debt_to_supply_index` and writes the supply index down, reducing every supplier's claim. A withdraw submitted at one index executes at a lower one, paying fewer tokens than the user observed when signing, with no way to bound the loss.

### Finding Description
- `withdraw(env, caller, account_id, withdrawals, to)` takes `Vec<(HubAssetKey, i128)>` of requested amounts only; a full exit (`amount = 0` → `WITHDRAW_ALL_SENTINEL`) pays whatever the floor-valued balance is at execution time. [1](#0-0) 
- `supply` similarly mints shares at the live index with no `min_shares` bound. [2](#0-1) 
- `clean_bad_debt` is permissionless (`requires caller authorization` only) and `liquidate` is permissionless; both reach `seize_positions`. [3](#0-2) 
- The borrow-side seize path calls `apply_bad_debt_to_supply_index`, which "scales [the supply index] down to socialize a loss across suppliers"; the pool README explicitly states `supply_index` is not monotone and "anything caching an index must tolerate a decrease." [4](#0-3) [5](#0-4) 
- A full withdrawal pays the floor-valued balance at the current index, so an index write-down between simulation/signing and execution reduces the payout with no revert option for the user. [6](#0-5) 

### Impact Explanation
A supplier who simulates a full exit and submits `withdraw` can receive strictly fewer tokens than quoted if a bad-debt socialization (or a liquidation seize leg socializing residual debt) lands first. This is a real, permanent loss of user funds bounded only by the socializeable bad debt in that (hub, asset) book — not just dust. On Stellar, transaction ordering/ledger-close timing is outside the signer's control, so the signer cannot guarantee the index they priced against.

### Likelihood Explanation
Requires a bad-debt event (an insolvent account at/below the dust cap, or liquidation residual) to exist in the same market the user is exiting, and a keeper/attacker to socialize it in between. `clean_bad_debt` is permissionless so no privilege is needed; losses from large write-downs are infrequent but the victim has zero protection when they occur. Medium.

### Recommendation
Add execution-time bounds at the controller/pool boundary: e.g., a `min_received`/`max_shares_burned` guard per withdraw leg (and `min_shares` for supply), or pin the expected `supply_index`/`MarketIndexRaw` in the call and revert if the committed index moved beyond a tolerance. The pool returns `PoolPositionMutation`/actual amounts already, so enforcement can compare the returned `actual_amount` against the caller's floor before committing.

### Proof of Concept
1. Alice supplies USDC via `supply(caller=alice, account_id=0, spoke_id, [(key, amount)])`; pool mints RAY shares at index `I`.
2. An account becomes insolvent with collateral at/below the dust cap. Eve (any address) calls `clean_bad_debt(caller=eve, account_id=victim)`, which executes `seize_positions` → `apply` borrow-side → `apply_bad_debt_to_supply_index`, lowering `supply_index` to `I' < I`.
3. Alice's pre-signed `withdraw(..., [(key, 0)], ...)` executes: `resolve_close_or_partial`/`resolve_withdrawal` burns all shares and pays `floor(shares × I')`, strictly less than the `floor(shares × I)` she simulated. The call succeeds; there is no parameter to make it revert.

### Citations

**File:** contracts/controller/src/lib.rs (L94-102)
```rust
    fn supply(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        assets: Vec<(HubAssetKey, i128)>,
    ) -> u64 {
        positions::process_supply(&env, &caller, account_id, spoke_id, &assets)
    }
```

**File:** contracts/controller/src/lib.rs (L120-128)
```rust
    fn withdraw(
        env: Env,
        caller: Address,
        account_id: u64,
        withdrawals: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) -> Vec<(HubAssetKey, i128)> {
        positions::process_withdraw(&env, &caller, account_id, &withdrawals, to)
    }
```

**File:** contracts/controller/src/lib.rs (L144-165)
```rust
    fn liquidate(
        env: Env,
        liquidator: Address,
        account_id: u64,
        debt_payments: Vec<(HubAssetKey, i128)>,
        seize_mode: SeizeMode,
    ) -> u64 {
        positions::liquidation::process_liquidation(
            &env,
            &liquidator,
            account_id,
            &debt_payments,
            seize_mode,
        )
    }

    /// Socializes insolvent debt into the supply index and removes the account
    /// when remaining collateral is at or below the dust cap. Permissionless;
    /// requires caller authorization.
    fn clean_bad_debt(env: Env, caller: Address, account_id: u64) {
        positions::liquidation::process_clean_bad_debt(&env, &caller, account_id);
    }
```

**File:** contracts/pool/src/ops/seize.rs (L24-28)
```rust
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
```

**File:** contracts/pool/README.md (L187-190)
```markdown
`borrow_index` only ever grows — `update_borrow_index` is its sole writer.
`supply_index` is **not** monotone: `apply_bad_debt_to_supply_index` scales it
down to socialize a loss across suppliers, floored at `SUPPLY_INDEX_FLOOR_RAW`
(`RAY/1000`). Anything caching an index must tolerate a decrease.
```

**File:** docs/reference/formulas.md (L55-57)
```markdown
A withdrawal request of at least the half-up displayed supply balance burns all
supply shares and pays their floor-valued balance. A repayment of at least the
ceiled debt balance burns all debt shares and refunds the excess.
```
