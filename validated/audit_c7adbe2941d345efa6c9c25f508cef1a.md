### Title
Unprivileged LP can fully drain a pool's vault and cause a permanent division-by-zero panic in `swap_base_input`/`swap_base_output` — ([File: programs/cp-swap/src/states/pool.rs])

### Summary
The analog of CVE-2019-2785 (an easily-triggered, repeatable server crash/hang caused by an internal InnoDB fault) exists in `PoolState::token_price_x32`, which performs unchecked integer division on live vault balances. Any liquidity provider can drive one side of the pool's post-fee vault balance to exactly zero through the normal, unprivileged `withdraw` instruction, after which every subsequent `swap_base_input`/`swap_base_output` call by any unprivileged swapper will panic with a division-by-zero, aborting the transaction and repeatedly “crashing” the swap path for the pool.

### Finding Description
`token_price_x32` computes the token price ratio with raw division and no zero-check: [1](#0-0) 

This function is invoked unconditionally, before any curve/liquidity validation, from `PoolState::get_swap_params`, which both `swap_base_input` and `swap_base_output` call at the very start of a swap: [2](#0-1) [3](#0-2) [4](#0-3) 

The `withdraw` instruction only rejects a withdrawal if the *computed recipient amounts* (`results.token_0_amount`/`results.token_1_amount`) are zero; it does not prevent a full withdrawal that leaves the pool's fee-adjusted vault balance (`vault_amount_without_fee`) at exactly zero on one or both sides: [5](#0-4) 

Since `lp_tokens_to_trading_tokens` uses `RoundDirection::Floor` and computes amounts proportionally to `lp_supply`, an LP burning all outstanding LP tokens (`lp_token_amount == pool_state.lp_supply`) will legitimately withdraw the *entire* non-fee vault balance, leaving `vault_amount_without_fee` at `(0, 0)` (or zero on one side if fee residue differs). From that point forward, `token_price_x32`'s division `... / token_0_amount` or `... / token_1_amount` divides by zero, causing the Anchor program to panic and abort any swap attempt.

### Impact Explanation
This is a repeatable, unprivileged denial-of-service against the swap path of the pool: once triggered, every `swap_base_input`/`swap_base_output` transaction targeting that pool fails with a panic until enough new liquidity is deposited to make both vault sides non-zero again. This mirrors the CVE's bug class — an easily reachable, network-facing operation causing a "hang or frequently repeatable crash" — but here the trigger is a completely permissionless action (an LP calling `withdraw`), and the crash blocks core AMM functionality (trading) for all other users of that pool until manual remediation (a fresh deposit) occurs. It does not directly permit theft of funds, but it degrades pool availability and can be weaponized by a single LP to grief a pool.

### Likelihood Explanation
High likelihood: any account holding all (or a proportionally large enough) LP tokens of a pool can trigger this with a single `withdraw` call using default, unprivileged instructions. Newly created or low-liquidity pools (e.g., right after `initialize`) are especially exposed, since the initial LP can immediately withdraw the whole position.

### Recommendation
Add explicit zero-checks in `token_price_x32` (and/or `vault_amount_without_fee`) and return a clean `ErrorCode` (e.g., `ErrorCode::ZeroTradingTokens`/new `EmptyPool` error) instead of relying on raw division, mirroring the checked-arithmetic pattern already used elsewhere in `pool.rs` (`checked_add`/`checked_sub` with `.ok_or(ErrorCode::MathOverflow)`). Additionally, consider preventing `withdraw` from draining a pool's tradable liquidity to zero (e.g., requiring a minimum reserve), consistent with how `CurveCalculator::validate_supply` enforces non-zero balances at `initialize`.

### Proof of Concept
1. Attacker (or any single LP) creates a pool via `initialize` and receives all initial LP tokens.
2. Attacker immediately calls `withdraw` with `lp_token_amount == pool_state.lp_supply`, which passes the `results.token_0_amount == 0 || results.token_1_amount == 0` check (both amounts are non-zero since lp_supply matches deposit) and transfers out the entire vault balance, leaving `vault_amount_without_fee` at `(0, 0)`.
3. Any user (including the attacker) then submits a `swap_base_input` or `swap_base_output` transaction against this pool.
4. `pool_state.get_swap_params` → `token_price_x32` executes `token_1_amount as u128 * Q32 as u128 / token_0_amount as u128` with `token_0_amount == 0`, causing a Rust panic and aborting the transaction, reproducibly, for every future swap attempt until new liquidity is deposited.

### Citations

**File:** programs/cp-swap/src/states/pool.rs (L223-229)
```rust
    pub fn token_price_x32(&self, vault_0: u64, vault_1: u64) -> Result<(u128, u128)> {
        let (token_0_amount, token_1_amount) = self.vault_amount_without_fee(vault_0, vault_1)?;
        Ok((
            token_1_amount as u128 * Q32 as u128 / token_0_amount as u128,
            token_0_amount as u128 * Q32 as u128 / token_1_amount as u128,
        ))
    }
```

**File:** programs/cp-swap/src/states/pool.rs (L277-295)
```rust
        ) = if input_vault_key == self.token_0_vault && output_vault_key == self.token_1_vault {
            let (total_input_token_amount, total_output_token_amount) =
                self.vault_amount_without_fee(input_vault_amount, output_vault_amount)?;
            let (token_0_price_x64, token_1_price_x64) =
                self.token_price_x32(input_vault_amount, output_vault_amount)?;

            (
                TradeDirection::ZeroForOne,
                total_input_token_amount,
                total_output_token_amount,
                token_0_price_x64,
                token_1_price_x64,
                self.is_creator_fee_on_input(TradeDirection::ZeroForOne)?,
            )
        } else if input_vault_key == self.token_1_vault && output_vault_key == self.token_0_vault {
            let (total_output_token_amount, total_input_token_amount) =
                self.vault_amount_without_fee(output_vault_amount, input_vault_amount)?;
            let (token_0_price_x64, token_1_price_x64) =
                self.token_price_x32(output_vault_amount, input_vault_amount)?;
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L98-103)
```rust
    } = pool_state.get_swap_params(
        ctx.accounts.input_vault.key(),
        ctx.accounts.output_vault.key(),
        ctx.accounts.input_vault.amount,
        ctx.accounts.output_vault.amount,
    )?;
```

**File:** programs/cp-swap/src/instructions/swap_base_output.rs (L36-41)
```rust
    } = pool_state.get_swap_params(
        ctx.accounts.input_vault.key(),
        ctx.accounts.output_vault.key(),
        ctx.accounts.input_vault.amount,
        ctx.accounts.output_vault.amount,
    )?;
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L112-126)
```rust
    let (total_token_0_amount, total_token_1_amount) = pool_state.vault_amount_without_fee(
        ctx.accounts.token_0_vault.amount,
        ctx.accounts.token_1_vault.amount,
    )?;
    let results = CurveCalculator::lp_tokens_to_trading_tokens(
        u128::from(lp_token_amount),
        u128::from(pool_state.lp_supply),
        u128::from(total_token_0_amount),
        u128::from(total_token_1_amount),
        RoundDirection::Floor,
    )
    .ok_or(ErrorCode::ZeroTradingTokens)?;
    if results.token_0_amount == 0 || results.token_1_amount == 0 {
        return err!(ErrorCode::ZeroTradingTokens);
    }
```
