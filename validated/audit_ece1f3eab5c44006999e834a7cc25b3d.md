### Title
Divergent LP Supply Accounting Between Program-Tracked `lp_supply` and Actual SPL Mint Supply Permanently Locks Pool Funds - (File: programs/cp-swap/src/instructions/withdraw.rs, programs/cp-swap/src/states/pool.rs)

### Summary
The pool maintains its own manually-tracked `lp_supply` counter in `PoolState` instead of relying on the LP mint's actual on-chain `supply` field. This counter is only ever mutated inside the program's `deposit` and `withdraw` instructions. However, SPL Token's native `Burn` instruction can be invoked directly by any LP token account owner without going through the cp-swap program at all, since burning only requires the token account owner's signature, not the mint authority. This creates two conflicting "burn" paths — the program's `withdraw` (which decrements `lp_supply` and returns underlying tokens) and the SPL Token program's native `burn` (which decrements the real mint supply but never touches `pool_state.lp_supply`) — exactly analogous to the reported conflicting-burn-mechanism bug class where one burn path updates internal accounting/backing while the other silently diverges from it.

### Finding Description
`PoolState::lp_supply` is defined and documented as the "True circulating supply without burns and lock ups" and is used as the denominator for all proportional share calculations in both `deposit` and `withdraw`: [1](#0-0) 

It is only updated inside the program's own instructions: [2](#0-1) [3](#0-2) 

The `withdraw` handler uses `pool_state.lp_supply` (not the LP mint's actual `supply` field) as the divisor when converting LP token amounts to trading token amounts via `CurveCalculator::lp_tokens_to_trading_tokens`: [4](#0-3) 

Because the LP mint authority is set to the pool PDA (`authority`) only for `MintTo`/`Burn`-authority-required operations, this does not prevent a normal LP holder from calling the SPL Token / Token-2022 program's `Burn` instruction directly against their own `owner_lp_token` account — `Burn` only requires the token account owner as signer, not the mint authority. This is a completely separate, unprivileged code path outside the cp-swap program that reduces the LP mint's real `supply` without ever calling into `deposit.rs`/`withdraw.rs`, so `pool_state.lp_supply` is never decremented to match.

### Impact Explanation
After such a direct burn, `pool_state.lp_supply` remains permanently overstated relative to the real number of LP tokens in circulation. Since `lp_supply` is the shared denominator used for every subsequent `deposit`/`withdraw` proportional calculation, the sum of amounts withdrawable by all remaining genuine LP token holders will be strictly less than the actual pooled assets. The residual assets corresponding to the "phantom" burned LP supply become permanently stuck in the pool vaults with no `lp_supply` units remaining to redeem them — a permanent freezing of LP funds and an insolvent/inconsistent internal accounting state, matching the "permanently locked" and "conflicting TVL/accounting" impact called out in the source report.

### Likelihood Explanation
Any LP token holder can trigger this unintentionally or maliciously with a single unprivileged transaction: obtain an LP token account (from any normal `deposit`), then invoke the SPL Token/Token-2022 `Burn` instruction directly against their own LP token account instead of calling the cp-swap `withdraw` instruction. No special privileges, validator control, or off-chain access is required — only ordinary token-account ownership, which any liquidity provider naturally has.

### Recommendation
Do not maintain a separately mutated `lp_supply` field as the source of truth for share calculations. Instead, read the LP mint's actual `supply` field (e.g., via the `lp_mint` account already passed into `deposit`/`withdraw`) at the time of calculation, so that any LP tokens burned through any code path are always reflected consistently, eliminating the possibility of divergence between the two accounting mechanisms.

### Proof of Concept
1. Attacker (or any LP) deposits liquidity via `deposit`, receiving `X` LP tokens; `pool_state.lp_supply` increases by `X` [5](#0-4) .
2. Instead of calling the cp-swap `withdraw` instruction, the holder submits a standalone transaction invoking the SPL Token (or Token-2022) program's `Burn` instruction directly on their `owner_lp_token` account for amount `X`, signed only by themselves as token account owner.
3. The LP mint's real `supply` decreases by `X`, but `pool_state.lp_supply` is untouched since no cp-swap instruction executed.
4. Any subsequent `withdraw` by other LPs computes `lp_tokens_to_trading_tokens` using the now-inflated `pool_state.lp_supply` denominator [6](#0-5) , so the sum of all future withdrawals can never fully drain the vaults — the share of tokens corresponding to the burned `X` LP units is permanently locked in `token_0_vault`/`token_1_vault` with no LP tokens left to claim it.

### Citations

**File:** programs/cp-swap/src/states/pool.rs (L104-105)
```rust
    /// True circulating supply without burns and lock ups
    pub lp_supply: u64,
```

**File:** programs/cp-swap/src/instructions/deposit.rs (L192-201)
```rust
    pool_state.lp_supply = pool_state.lp_supply.checked_add(lp_token_amount).unwrap();

    token_mint_to(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
        ctx.accounts.lp_mint.to_account_info(),
        ctx.accounts.owner_lp_token.to_account_info(),
        lp_token_amount,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
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

**File:** programs/cp-swap/src/instructions/withdraw.rs (L178-186)
```rust
    pool_state.lp_supply = pool_state.lp_supply.checked_sub(lp_token_amount).unwrap();
    token_burn(
        ctx.accounts.owner.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
        ctx.accounts.lp_mint.to_account_info(),
        ctx.accounts.owner_lp_token.to_account_info(),
        lp_token_amount,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;
```
