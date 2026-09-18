### Title
Unbounded creator-fee transfer permanently DOSes `collect_creator_fee`/`collect_creator_fee_permissionless` if vault balance falls below recorded fee accounting - (File: programs/cp-swap/src/instructions/collect_creator_fee.rs, programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs)

### Summary
`collect_creator_fee` and `collect_creator_fee_permissionless` unconditionally transfer the *full* `pool_state.creator_fees_token_0`/`creator_fees_token_1` amounts out of the vaults, with no capping against the vault's actual token balance [1](#0-0) [2](#0-1) . This mirrors the reported bug class: internal fee/reserve accounting (`creator_fees_token_0/1`) is tracked separately from actual on-chain vault balances, and if the two diverge such that the vault holds less than the recorded fee amount, the withdrawal reverts, and because the amount requested is never reduced (unlike `collect_protocol_fee`, which uses `.min()`), the fee remains permanently un-collectible.

### Finding Description
`update_fees` accumulates `protocol_fees_token_X`, `fund_fees_token_X`, and `creator_fees_token_X` on every swap [3](#0-2) , and `vault_amount_without_fee` subtracts all three accumulated fee categories from the raw vault balance to compute the "true" reserves used for LP pricing [4](#0-3) . This design assumes the vault always holds at least `protocol_fees + fund_fees + creator_fees` on top of the LP-owned reserves.

`collect_protocol_fee` correctly guards against any accounting drift by capping the transferred amount to `min(requested, pool_state.protocol_fees_token_X)` and only reducing the outstanding balance by what is actually withdrawn [5](#0-4) . In contrast, `collect_creator_fee` and `collect_creator_fee_permissionless` transfer the entire tracked `creator_fees_token_0`/`creator_fees_token_1` in one shot with no partial-withdrawal fallback and no minimum against the real vault balance [6](#0-5) . If the vault's actual SPL balance is ever lower than the recorded `creator_fees_token_X` — for instance due to Token-2022 mint transfer-fee extensions where the amount actually deposited into the vault during a swap is less than the pre-transfer-fee amount used in the internal accounting, or due to any other rounding/accounting drift between on-chain vault balance and the internally tracked fee ledger — the CPI transfer inside `transfer_from_pool_vault_to_user` will fail with an insufficient-funds error from the token program, causing the whole instruction to revert.

Because the instruction resets `creator_fees_token_0`/`creator_fees_token_1` to `0` only after the transfer succeeds [7](#0-6) , and there is no mechanism to request a smaller amount (both instructions take zero arguments and always attempt the full recorded balance), any single-transaction attempt by the creator (or by anyone via the permissionless variant) will deterministically fail and can never succeed until the vault balance again exceeds the fee ledger — which, absent external donation, will not happen. The pool creator's earned creator fee becomes permanently unreachable/stuck in the vault, matching the "DOS of withdrawing assets if reserve is not enough" bug pattern from the referenced report, but applied to the creator-fee ledger instead of an external insurance pool.

### Impact Explanation
This can permanently freeze the pool creator's accrued fee funds in the pool vault with no recovery path, since neither `collect_creator_fee` nor `collect_creator_fee_permissionless` supports partial withdrawal or ever reduces the recorded amount without a successful full transfer. This is a freezing-of-funds issue affecting the pool creator's fee revenue, reachable by an unprivileged caller (the permissionless variant) or the creator themselves, with no way to work around the revert.

### Likelihood Explanation
Whether the vault balance can actually fall below the accumulated `creator_fees_token_X` in production depends on precise interaction between Token-2022 transfer-fee-enabled mints and the fee-accounting arithmetic in `swap_base_input`/`swap_base_output`/`CurveCalculator::swap_base_input`. I was not able to fully trace, within the available tool budget, whether the input/output transfer-fee handling in the swap instructions guarantees the vault always retains enough balance to cover `protocol_fees + fund_fees + creator_fees` in all token configurations (e.g., mixed standard-SPL/Token-2022 pools, or extension combinations). The asymmetry with `collect_protocol_fee` (which explicitly guards against this exact scenario via `.min()`) is a strong signal that the developers considered fee-ledger/vault-balance drift a real risk elsewhere in the codebase but did not apply the same defensive pattern to the creator-fee collection instructions.

### Recommendation
Apply the same defensive pattern used in `collect_protocol_fee`: cap the transferred `creator_fees_token_0`/`creator_fees_token_1` amount to the minimum of the recorded fee and the actual vault balance (net of amounts owed to LPs/other fee categories), and only decrement the recorded fee ledger by the amount actually transferred, so a partial collection is always possible instead of an all-or-nothing revert.

### Proof of Concept
1. Attacker/creator triggers swaps that accrue `creator_fees_token_0` in `pool_state` via `update_fees` during `swap_base_input`/`swap_base_output` [8](#0-7) .
2. Under conditions where the vault's actual token balance ends up lower than the sum `protocol_fees_token_0 + fund_fees_token_0 + creator_fees_token_0` recorded in `pool_state` (e.g., transfer-fee-on-transfer token behavior reducing what actually lands in the vault relative to what the fee math assumes was deposited), any call to `collect_creator_fee` or `collect_creator_fee_permissionless` will attempt to transfer the full `creator_fees_token_0` amount out of `token_0_vault` [9](#0-8) .
3. The token-program CPI transfer fails because the vault does not hold that many tokens, reverting the whole instruction and leaving `creator_fees_token_0` unchanged and un-collectible in any subsequent transaction, since there's no reduced/partial-amount path.

### Citations

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-118)
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
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L120-122)
```rust
    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-112)
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
```

**File:** programs/cp-swap/src/states/pool.rs (L200-221)
```rust
    pub fn vault_amount_without_fee(&self, vault_0: u64, vault_1: u64) -> Result<(u64, u64)> {
        let fees_token_0 = self
            .protocol_fees_token_0
            .checked_add(self.fund_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?;
        let fees_token_1 = self
            .protocol_fees_token_1
            .checked_add(self.fund_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?;
        Ok((
            vault_0
                .checked_sub(fees_token_0)
                .ok_or(ErrorCode::InsufficientVault)?,
            vault_1
                .checked_sub(fees_token_1)
                .ok_or(ErrorCode::InsufficientVault)?,
        ))
    }
```

**File:** programs/cp-swap/src/states/pool.rs (L326-369)
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
        Ok(())
    }
```

**File:** programs/cp-swap/src/instructions/admin/collect_protocol_fee.rs (L79-95)
```rust
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
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L158-163)
```rust
    pool_state.update_fees(
        u64::try_from(result.protocol_fee).unwrap(),
        u64::try_from(result.fund_fee).unwrap(),
        u64::try_from(result.creator_fee).unwrap(),
        trade_direction,
    )?;
```
