Based on my investigation, I found a plausible analog, but I was unable to directly view the body of `pool_state.vault_amount_without_fee()` (in `programs/cp-swap/src/states/pool.rs`) before running out of tool calls, so the exact fee-exclusion list in that function is inferred from call sites and naming conventions rather than confirmed line-by-line. I flag this uncertainty explicitly below.

### Title
LP withdrawals and creator-fee collection may share an unsegregated claim on the same pool vault balance - (File: programs/cp-swap/src/states/pool.rs, programs/cp-swap/src/instructions/withdraw.rs, programs/cp-swap/src/instructions/collect_creator_fee.rs)

### Summary
The pool vault token accounts hold, in a single balance, both LP-owned liquidity and multiple classes of un-collected fees: `protocol_fees_token_{0,1}`, `fund_fees_token_{0,1}`, and `creator_fees_token_{0,1}` [1](#0-0) . `withdraw()` computes the LP-redeemable amount from `pool_state.vault_amount_without_fee(...)`, which is meant to strip out fee amounts that don't belong to LPs before applying the constant-product-based LP-to-token conversion [2](#0-1) . This is analogous to the Derby report's root cause: two different classes of claimants (LP stakers vs. the pool creator collecting `creator_fees_token_0/1`) can end up drawing against the same physical vault balance if the "amount owed to LPs" calculation doesn't fully carve out every outstanding, separately-tracked fee bucket.

### Finding Description
Three independent fee buckets accrue in the same vault token account on every swap via `update_fees()`: `protocol_fees_token_0/1`, `fund_fees_token_0/1`, and `creator_fees_token_0/1` [3](#0-2) . Each is redeemable independently and at different times by different parties: the protocol authority via `collect_protocol_fee` [4](#0-3) , the fund owner via `collect_fund_fee` [5](#0-4) , and the pool creator via `collect_creator_fee` / `collect_creator_fee_permissionless` [6](#0-5) [7](#0-6) .

Meanwhile, `withdraw()` derives the LP-owned reserve via `vault_amount_without_fee(vault_0_amount, vault_1_amount)` and feeds that into `CurveCalculator::lp_tokens_to_trading_tokens` to determine how much of the vault an LP can redeem per burned LP token [2](#0-1) . The same helper is used for pricing in swaps [8](#0-7) . If this single helper does not deduct **all three** fee buckets (in particular, if `creator_fees_token_0/1` — a newer field added alongside the `collect_creator_fee` feature — is omitted from the subtraction), then the value LPs are entitled to redeem overlaps with the value the creator is separately entitled to collect. This is structurally the same defect described in the Derby report: two independent claimants (LPs and the creator) both have a claim to the same underlying tokens sitting in the vault, and whichever party withdraws/collects last can be left short.

I was not able to confirm the exact subtraction list inside `vault_amount_without_fee` before running out of tool budget — this is the one detail that determines whether the bug is real or the fees are properly segregated. All fee-accrual and fee-collection code paths that support the theory are cited above.

### Impact Explanation
If `vault_amount_without_fee` does not net out `creator_fees_token_0/1`, LPs can withdraw a share of the vault that includes yet-unclaimed creator fees, and later `collect_creator_fee`/`collect_creator_fee_permissionless` would attempt to `transfer_from_pool_vault_to_user` the recorded `creator_fees_token_0/1` amount even though the vault balance has already been drawn down by LPs [9](#0-8) . Depending on ordering, either LPs are shorted (their pro-rata share silently included fees that get siphoned off later) or the creator's fee collection can fail/underflow due to insufficient vault balance, i.e., a fee-ledger/vault insolvency — matching the "last user cannot withdraw" impact pattern in the referenced report.

### Likelihood Explanation
Creator fees accumulate on every swap where `enable_creator_fee` is set [10](#0-9) , so the overlapping-claim window grows continuously with trading activity and only needs an LP withdrawal to occur before the creator's next fee collection — a normal, permissionless, frequently-occurring sequence of transactions, not a contrived edge case.

### Recommendation
Confirm (and if necessary fix) that `vault_amount_without_fee` subtracts `protocol_fees_token_0/1`, `fund_fees_token_0/1`, **and** `creator_fees_token_0/1` from the raw vault balances before computing LP conversions in both `withdraw()` and swap pricing, so LPs never have a claim on tokens reserved for protocol/fund/creator fee collection.

### Proof of Concept
1. Create a pool with `enable_creator_fee = true` and a nonzero `creator_fee_rate`.
2. Perform swaps that accrue `creator_fees_token_0/1` into the pool vault (funds physically remain in `token_0_vault`/`token_1_vault`).
3. Call `withdraw()` for all LP tokens; if `vault_amount_without_fee` does not exclude `creator_fees_token_0/1`, the LP's redemption amount is computed against a vault balance that still includes uncollected creator fees, draining tokens that are also owed to the creator.
4. Call `collect_creator_fee` afterward — the transfer of `creator_fees_token_0/1` recorded in `pool_state` [11](#0-10)  may now exceed the actual vault balance, causing failure or short-paying whichever party acts last.

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

**File:** programs/cp-swap/src/states/pool.rs (L318-324)
```rust
    pub fn adjust_creator_fee_rate(&self, creator_fee_rate: u64) -> u64 {
        if self.enable_creator_fee {
            creator_fee_rate
        } else {
            0
        }
    }
```

**File:** programs/cp-swap/src/states/pool.rs (L326-367)
```rust
    pub fn update_fees(
        &mut self,
        protocol_fee: u64,
        fund_fee: u64,
        creator_fee: u64,
        direction: TradeDirection,
    ) -> Result<()> {
        if !self.enable_creator_fee {
            require_eq!(creator_fee, 0)
        }
        let is_creator_fee_on_input = self.is_creator_fee_on_input(direction)?;
        match direction {
            TradeDirection::ZeroForOne => {
                self.protocol_fees_token_0 = self
                    .protocol_fees_token_0
                    .checked_add(protocol_fee)
                    .unwrap();
                self.fund_fees_token_0 = self.fund_fees_token_0.checked_add(fund_fee).unwrap();

                if is_creator_fee_on_input {
                    self.creator_fees_token_0 =
                        self.creator_fees_token_0.checked_add(creator_fee).unwrap();
                } else {
                    self.creator_fees_token_1 =
                        self.creator_fees_token_1.checked_add(creator_fee).unwrap();
                }
            }
            TradeDirection::OneForZero => {
                self.protocol_fees_token_1 = self
                    .protocol_fees_token_1
                    .checked_add(protocol_fee)
                    .unwrap();
                self.fund_fees_token_1 = self.fund_fees_token_1.checked_add(fund_fee).unwrap();
                if is_creator_fee_on_input {
                    self.creator_fees_token_1 =
                        self.creator_fees_token_1.checked_add(creator_fee).unwrap();
                } else {
                    self.creator_fees_token_0 =
                        self.creator_fees_token_0.checked_add(creator_fee).unwrap();
                }
            }
        };
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

**File:** programs/cp-swap/src/instructions/admin/collect_protocol_fee.rs (L74-99)
```rust
pub fn collect_protocol_fee(
    ctx: Context<CollectProtocolFee>,
    amount_0_requested: u64,
    amount_1_requested: u64,
) -> Result<()> {
    let amount_0: u64;
    let amount_1: u64;
    let auth_bump: u8;
    {
        let mut pool_state = ctx.accounts.pool_state.load_mut()?;

        amount_0 = amount_0_requested.min(pool_state.protocol_fees_token_0);
        amount_1 = amount_1_requested.min(pool_state.protocol_fees_token_1);

        pool_state.protocol_fees_token_0 = pool_state
            .protocol_fees_token_0
            .checked_sub(amount_0)
            .unwrap();
        pool_state.protocol_fees_token_1 = pool_state
            .protocol_fees_token_1
            .checked_sub(amount_1)
            .unwrap();

        auth_bump = pool_state.auth_bump;
        pool_state.recent_epoch = Clock::get()?.epoch;
    }
```

**File:** programs/cp-swap/src/instructions/admin/collect_fund_fee.rs (L73-90)
```rust
pub fn collect_fund_fee(
    ctx: Context<CollectFundFee>,
    amount_0_requested: u64,
    amount_1_requested: u64,
) -> Result<()> {
    let amount_0: u64;
    let amount_1: u64;
    let auth_bump: u8;
    {
        let mut pool_state = ctx.accounts.pool_state.load_mut()?;
        amount_0 = amount_0_requested.min(pool_state.fund_fees_token_0);
        amount_1 = amount_1_requested.min(pool_state.fund_fees_token_1);

        pool_state.fund_fees_token_0 = pool_state.fund_fees_token_0.checked_sub(amount_0).unwrap();
        pool_state.fund_fees_token_1 = pool_state.fund_fees_token_1.checked_sub(amount_1).unwrap();
        auth_bump = pool_state.auth_bump;
        pool_state.recent_epoch = Clock::get()?.epoch;
    }
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-122)
```rust
pub fn collect_creator_fee(ctx: Context<CollectCreatorFee>) -> Result<()> {
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    let creator_fees_token_0 = pool_state.creator_fees_token_0;
    let creator_fees_token_1 = pool_state.creator_fees_token_1;
    if creator_fees_token_0 == 0 && creator_fees_token_1 == 0 {
        return err!(ErrorCode::NoFeeCollect);
    }

    let signer_seeds: &[&[u8]] = &[crate::AUTH_SEED.as_bytes(), &[ctx.bumps.authority]];

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.creator_token_0.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        ctx.accounts.token_0_program.to_account_info(),
        creator_fees_token_0,
        ctx.accounts.vault_0_mint.decimals,
        &[signer_seeds],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.creator_token_1.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        ctx.accounts.token_1_program.to_account_info(),
        creator_fees_token_1,
        ctx.accounts.vault_1_mint.decimals,
        &[signer_seeds],
    )?;

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-127)
```rust
pub fn collect_creator_fee_permissionless(
    ctx: Context<CollectCreatorFeePermissionless>,
) -> Result<()> {
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    let creator_fees_token_0 = pool_state.creator_fees_token_0;
    let creator_fees_token_1 = pool_state.creator_fees_token_1;
    if creator_fees_token_0 == 0 && creator_fees_token_1 == 0 {
        return err!(ErrorCode::NoFeeCollect);
    }

    let signer_seeds: &[&[u8]] = &[crate::AUTH_SEED.as_bytes(), &[ctx.bumps.authority]];

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.creator_token_0.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        ctx.accounts.token_0_program.to_account_info(),
        creator_fees_token_0,
        ctx.accounts.vault_0_mint.decimals,
        &[signer_seeds],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.creator_token_1.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        ctx.accounts.token_1_program.to_account_info(),
        creator_fees_token_1,
        ctx.accounts.vault_1_mint.decimals,
        &[signer_seeds],
    )?;

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```
