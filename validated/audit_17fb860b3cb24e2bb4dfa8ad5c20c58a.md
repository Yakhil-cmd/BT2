### Title
Direct SPL-Token burn of LP tokens desyncs `PoolState.lp_supply` from the real LP mint supply, permanently locking a proportional share of vault funds - (File: `programs/cp-swap/src/instructions/withdraw.rs`, `programs/cp-swap/src/instructions/deposit.rs`, `programs/cp-swap/src/states/pool.rs`)

### Summary
`PoolState.lp_supply` is a cached bookkeeping counter that the program only mutates inside its own `deposit`/`withdraw` instructions [1](#0-0) . Any LP-token holder is the token-account owner and can therefore invoke the standard SPL Token/Token-2022 `Burn` instruction directly on their own `owner_lp_token` account and the pool's `lp_mint`, without ever calling the Raydium `withdraw` instruction. This reduces the real, on-chain LP mint supply while leaving `pool_state.lp_supply` unchanged, exactly mirroring the original L1/L2 ECO bug where a user could call `burn` on their own tokens outside the bridge's accounted withdraw path, permanently stranding the backing asset.

### Finding Description
`lp_supply` is used as the sole denominator to convert between LP tokens and underlying token_0/token_1 amounts in both `deposit` and `withdraw`: [2](#0-1) [3](#0-2) 

The program only decrements/increments this field when a user goes through `deposit`/`withdraw`: [4](#0-3) [5](#0-4) 

Nothing in the program cross-checks `pool_state.lp_supply` against the actual `Mint::supply` of `lp_mint`; there is no reconciliation call anywhere in the codebase. Because the `lp_mint`'s SPL "burn authority" for a `Burn` CPI is simply the owner of the source token account (the LP holder themselves, as used identically in `withdraw.rs:179-186` where `ctx.accounts.owner` is the burn authority), a user can submit a standalone SPL Token `Burn` instruction against their own `owner_lp_token` account/`lp_mint`, bypassing the Raydium program entirely. This destroys real LP supply while `pool_state.lp_supply` keeps counting the burned tokens as still outstanding.

### Impact Explanation
Once `pool_state.lp_supply` is inflated relative to the true circulating LP supply, every subsequent `withdraw` call computes `lp_tokens_to_trading_tokens(lp_token_amount, pool_state.lp_supply, total_token_0, total_token_1, Floor)` using an artificially large denominator. No possible sum of the (now-reduced) real outstanding LP tokens can equal `pool_state.lp_supply`, so the fraction of `token_0_vault`/`token_1_vault` corresponding to the burned LP tokens can never be withdrawn by any remaining LP holder — it is permanently locked in the pool vaults. This is a direct analog of the reported issue (funds permanently locked because a user-triggered burn bypasses the protocol's own withdraw/accounting path) and results in permanent freezing of LP funds.

### Likelihood Explanation
Any liquidity provider holding LP tokens can trigger this with a single, unprivileged, standard SPL Token instruction using their own account and their own signature — no special role, no protocol bug in the swap logic itself, and no cooperation from the pool creator or admin is required. The only requirement is owning LP tokens, which is the normal state of any depositor.

### Recommendation
Do not rely on a separately-tracked `pool_state.lp_supply` counter that can diverge from the actual LP mint supply. Either:
1. Read `lp_mint.supply` directly from the on-chain `Mint` account when computing `lp_tokens_to_trading_tokens` in both `deposit` and `withdraw`, instead of the cached `pool_state.lp_supply` field, or
2. If the cached counter is kept for CU efficiency, periodically reconcile it against `lp_mint.supply` (e.g., assert equality on every `deposit`/`withdraw` call and refuse to proceed on mismatch), so that externally burned tokens are detected and the true circulating supply is always used for share calculations.

### Proof of Concept
1. LP1 deposits, receiving LP tokens (`pool_state.lp_supply` increases via `deposit.rs:192`).
2. LP1 constructs a transaction with a raw SPL Token `Burn` instruction (`token_program::burn` or `token_2022::burn`), specifying their own `owner_lp_token` account as source, `lp_mint` as mint, and themselves as authority — this instruction never touches the `raydium-cp-swap` program, so `pool_state.lp_supply` is not updated.
3. The real LP mint supply drops by the burned amount, but `pool_state.lp_supply` retains the old (higher) value.
4. Any subsequent `withdraw` by remaining LPs computes `lp_tokens_to_trading_tokens(lp_token_amount, pool_state.lp_supply /* stale, too high */, total_token_0, total_token_1, Floor)` at `withdraw.rs:116-123`, under-crediting them relative to their true share; the delta corresponding to LP1's burned tokens remains stuck in `token_0_vault`/`token_1_vault` forever, since the sum of all real LP token balances can never reach `pool_state.lp_supply` again.

### Citations

**File:** programs/cp-swap/src/states/pool.rs (L231-250)
```rust
    pub fn update_lp_supply(
        &mut self,
        liquidity_delta: u64,
        add: bool,
        recent_epoch: u64,
    ) -> Result<()> {
        if add {
            self.lp_supply = self
                .lp_supply
                .checked_add(liquidity_delta)
                .ok_or(ErrorCode::MathOverflow)?;
        } else {
            self.lp_supply = self
                .lp_supply
                .checked_sub(liquidity_delta)
                .ok_or(ErrorCode::MathOverflow)?;
        }
        self.recent_epoch = recent_epoch;
        Ok(())
    }
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L112-123)
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

**File:** programs/cp-swap/src/instructions/deposit.rs (L99-110)
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
        RoundDirection::Ceiling,
    )
    .ok_or(ErrorCode::ZeroTradingTokens)?;
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
