### Title
Fee-ledger vs. vault-balance mismatch can permanently freeze deposit/withdraw/swap - (File: `programs/cp-swap/src/states/pool.rs`)

### Summary
`PoolState::vault_amount_without_fee` computes the trading-available liquidity by subtracting the accumulated, uncollected `protocol_fees`/`fund_fees`/`creator_fees` counters from the *live* SPL token-account balance of each vault, using `checked_sub` that errors (`ErrorCode::InsufficientVault`) on underflow. [1](#0-0)  This mirrors the reported bug class exactly: an accounting value that is derived by subtracting a monotonically-growing internal counter from an externally-influenced balance, with an unconditional assumption that the balance always dominates the counter.

### Finding Description
`vault_amount_without_fee` is called from `swap_base_input`/`swap_base_output` (via `get_swap_params`), `deposit`, and `withdraw` before every liquidity-affecting instruction. [2](#0-1) [3](#0-2)  It assumes `vault_0.amount >= protocol_fees_token_0 + fund_fees_token_0 + creator_fees_token_0` (and likewise for token 1) at all times.

The fee counters are incremented purely based on the curve's calculated `protocol_fee`/`fund_fee`/`creator_fee` outputs from `update_fees`, independent of what actually lands in the vault. [4](#0-3)  Meanwhile the vault's live balance can be reduced relative to what the fee ledger expects whenever the underlying SPL Token-2022 mint applies a `TransferFee` on the inbound transfer: in `swap_base_input`, `input_transfer_amount = amount_in` (the pre-fee amount) is transferred into the vault, but only `actual_amount_in = amount_in - transfer_fee` is used to derive `total_input_token_amount`/fee splits going forward. [5](#0-4)  If the mint's transfer-fee configuration changes (fee rate raised, e.g., via a fee-config authority action or an epoch-based fee schedule change on a Token-2022 mint) between when a swap's `constant_before` snapshot is taken and when the actual on-chain transfer executes, the SPL Token-2022 program can deduct a different (larger) transfer fee than what `get_transfer_fee` computed, so less than `input_transfer_amount - transfer_fee` may actually land in the vault, while `pool_state.update_fees` has already committed the pre-computed `protocol_fee`/`fund_fee`/`creator_fee` values to the fee ledger. Once the ledger has "reserved" more than the vault physically holds — because of any such drift between assumed and actual transferred/received amounts across repeated swaps — the very next call to `vault_amount_without_fee` underflows and reverts with `InsufficientVault`.

Because `vault_amount_without_fee` gates every `deposit`, `withdraw`, and `swap` call, once the ledger/vault-balance relationship is violated for a pool, **all liquidity operations on that pool revert forever**, exactly as with the stETH negative-rebase report where `lastRoundAssets - totalAssets` underflowed and blocked round-ending until a positive-yield-only condition was met.

### Impact Explanation
If the fee-ledger counters (`protocol_fees_token_x + fund_fees_token_x + creator_fees_token_x`) ever exceed the vault's real token balance for either mint, every subsequent `deposit`, `withdraw`, `swap_base_input`, and `swap_base_output` call for that pool reverts with `ErrorCode::InsufficientVault`, permanently freezing all LP funds and trading in the pool (no admin-only recovery path exists in these unprivileged-reachable instructions). This satisfies "permanent freezing of user or LP funds."

### Likelihood Explanation
This requires a Token-2022 mint whose transfer-fee configuration can produce a discrepancy between the fee amount computed by `get_transfer_fee` at the time of the swap's fee-split calculation and the fee actually deducted by the SPL Token-2022 program during the real transfer (e.g., an epoch boundary crossing between fee snapshot and execution, given `get_epoch_fee` is epoch-dependent). This is a narrower, harder-to-trigger condition than the stETH slashing scenario (which happens organically), so likelihood is lower and depends on pool creators choosing/being forced to support a Token-2022 mint with mutable/epoch-varying transfer fees. I was not able to fully verify from the indexed code whether `get_transfer_fee`'s epoch snapshot is guaranteed consistent with the epoch used by the actual CPI transfer within the same transaction (both should read `Clock::get()?.epoch` in the same instruction, which would normally prevent mid-instruction drift) — this needs further verification in `programs/cp-swap/src/utils/token.rs` to confirm whether cross-instruction epoch transitions or fee-config updates could be interleaved before the transfer CPI executes.

### Recommendation
In `vault_amount_without_fee` (`programs/cp-swap/src/states/pool.rs:200-221`), avoid an unconditional `checked_sub` that can permanently deadlock the pool. Instead, clamp the fee subtraction (e.g., `vault_0.saturating_sub(fees_token_0)`) so a ledger/balance mismatch degrades gracefully (fees effectively capped at the available balance) rather than reverting every future instruction, and add invariant checks/tests ensuring the fee ledger can never be incremented beyond what is actually receivable into the vault (i.e., derive fee amounts strictly from confirmed post-transfer vault deltas rather than pre-transfer estimates).

### Proof of Concept
Not independently reproduced against a live Token-2022 mint with a shifting transfer-fee schedule; the analysis is based on static code tracing of `vault_amount_without_fee`, `update_fees`, and the transfer-fee handling in `swap_base_input`. A concrete PoC would require: (1) creating a pool with a Token-2022 mint configured with a transfer-fee extension, (2) scheduling/authorizing a transfer-fee-rate change to take effect at a specific epoch, (3) executing a swap whose fee computation (`get_transfer_fee`) is based on the pre-change rate while the actual CPI transfer lands in a post-change epoch with a higher fee, repeating until `protocol_fees_token_x + fund_fees_token_x + creator_fees_token_x > vault_x.amount`, then observing that `deposit`/`withdraw`/`swap` calls revert with `InsufficientVault` indefinitely. [6](#0-5)

### Citations

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

**File:** programs/cp-swap/src/instructions/withdraw.rs (L112-115)
```rust
    let (total_token_0_amount, total_token_1_amount) = pool_state.vault_amount_without_fee(
        ctx.accounts.token_0_vault.amount,
        ctx.accounts.token_1_vault.amount,
    )?;
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L85-120)
```rust
    let transfer_fee =
        get_transfer_fee(&ctx.accounts.input_token_mint.to_account_info(), amount_in)?;
    // Take transfer fees into account for actual amount transferred in
    let actual_amount_in = amount_in.saturating_sub(transfer_fee);
    require_gt!(actual_amount_in, 0);

    let SwapParams {
        trade_direction,
        total_input_token_amount,
        total_output_token_amount,
        token_0_price_x64,
        token_1_price_x64,
        is_creator_fee_on_input,
    } = pool_state.get_swap_params(
        ctx.accounts.input_vault.key(),
        ctx.accounts.output_vault.key(),
        ctx.accounts.input_vault.amount,
        ctx.accounts.output_vault.amount,
    )?;
    let constant_before = u128::from(total_input_token_amount)
        .checked_mul(u128::from(total_output_token_amount))
        .unwrap();

    let creator_fee_rate =
        pool_state.adjust_creator_fee_rate(ctx.accounts.amm_config.creator_fee_rate);
    let result = CurveCalculator::swap_base_input(
        u128::from(actual_amount_in),
        u128::from(total_input_token_amount),
        u128::from(total_output_token_amount),
        ctx.accounts.amm_config.trade_fee_rate,
        creator_fee_rate,
        ctx.accounts.amm_config.protocol_fee_rate,
        ctx.accounts.amm_config.fund_fee_rate,
        is_creator_fee_on_input,
    )
    .ok_or(ErrorCode::ZeroTradingTokens)?;
```

**File:** programs/cp-swap/src/utils/token.rs (L253-286)
```rust
/// Calculate the fee for output amount
pub fn get_transfer_inverse_fee(mint_info: &AccountInfo, post_fee_amount: u64) -> Result<u64> {
    if *mint_info.owner == Token::id() {
        return Ok(0);
    }
    if post_fee_amount == 0 {
        return err!(ErrorCode::InvalidInput);
    }
    let mint_data = mint_info.try_borrow_data()?;
    let mint = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;

    let fee = if let Ok(transfer_fee_config) = mint.get_extension::<TransferFeeConfig>() {
        let epoch = Clock::get()?.epoch;

        let transfer_fee = transfer_fee_config.get_epoch_fee(epoch);
        if u16::from(transfer_fee.transfer_fee_basis_points) == MAX_FEE_BASIS_POINTS {
            u64::from(transfer_fee.maximum_fee)
        } else {
            let transfer_fee = transfer_fee_config
                .calculate_inverse_epoch_fee(epoch, post_fee_amount)
                .unwrap();
            let transfer_fee_for_check = transfer_fee_config
                .calculate_epoch_fee(epoch, post_fee_amount.checked_add(transfer_fee).unwrap())
                .unwrap();
            if transfer_fee != transfer_fee_for_check {
                return err!(ErrorCode::TransferFeeCalculateNotMatch);
            }
            transfer_fee
        }
    } else {
        0
    };
    Ok(fee)
}
```
