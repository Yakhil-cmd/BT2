## Analog Found

### Title
JIT (Just-In-Time) Liquidity Attack Allows Flashloaned Deposits to Skim LP Trading Fees Without Bearing Pool Risk - (File: `programs/cp-swap/src/instructions/deposit.rs`, `programs/cp-swap/src/instructions/withdraw.rs`, `programs/cp-swap/src/states/pool.rs`)

### Summary
The core flaw in the referenced bEth report is that a global reward index is updated as a simple ratio of `new_reward_balance / total_balance`, without regard to *when* a user's balance grew relative to *when* the reward accrued — letting a flashloaned/whale depositor capture a share of freshly pushed rewards proportional only to their instantaneous balance, not their time-weighted contribution. `raydium-cp-swap` reproduces the identical root cause: LP-token trading-fee revenue accrues directly into the pool vault balances, and a user's redeemable share of that balance is determined purely by `lp_token_amount / lp_supply` at redemption time, with no time-weighting or lock-up, and — critically — depositing/withdrawing large amounts carries **no price risk**, because both operations are computed on the *current* pool ratio.

### Finding Description
In `CurveCalculator::swap_base_input` (`programs/cp-swap/src/curve/calculator.rs:95-143`), the "trade fee" collected on a swap is split into `protocol_fee`, `fund_fee`, and `creator_fee`, all of which are explicitly tracked and later subtracted out via `PoolState::vault_amount_without_fee` (`programs/cp-swap/src/states/pool.rs:200-220`). The remaining portion of `trade_fee` (i.e., `trade_fee - protocol_fee - fund_fee`, the LP-holder's share) is **not** tracked separately — it simply stays in the vault as part of the raw token balance, because `pool_state.update_fees()` (`programs/cp-swap/src/states/pool.rs:326-369`) only records `protocol_fee`, `fund_fee`, and `creator_fee`. This raw vault balance directly increases `total_token_0_amount`/`total_token_1_amount` returned by `vault_amount_without_fee`, which is the basis for LP-token minting/burning ratios in both `deposit()` (`programs/cp-swap/src/instructions/deposit.rs:99-110`) and `withdraw()` (`programs/cp-swap/src/instructions/withdraw.rs:112-123`), both of which call `CurveCalculator::lp_tokens_to_trading_tokens` using the *current* vault totals and *current* `lp_supply`.

Because deposits and withdrawals mint/burn LP tokens strictly proportional to the pool's current ratio (not a time-weighted or historically-anchored ratio), an attacker can:
1. Front-run a large pending swap by calling `deposit()` with a flashloaned or borrowed sum, minting a large fraction of `lp_supply` — this carries **zero price risk** because deposit preserves the token_0/token_1 ratio exactly (unlike a swap).
2. Let (or force via a bundle) the victim's `swap_base_input`/`swap_base_output` execute, whose LP-fee remainder is credited straight into the vault balance the attacker now has a large claim on.
3. Immediately call `withdraw()`, redeeming LP tokens at the new (fee-inflated) ratio, thereby capturing a share of the just-generated trading fee proportional to their momentary stake, then repaying the flashloan.

This is structurally identical to the bEth report's `update_global_index()` flaw: a balance/stake spike that occurs *immediately adjacent* to a reward/fee event nets the attacker a disproportionate payout, at the expense of the genuine, longer-term liquidity providers who bore the actual pool risk.

### Impact Explanation
Each successful sandwich siphons a portion of the trade-fee revenue that legitimate long-term LPs would otherwise have earned, since LP-fee accrual is undifferentiated from any other balance in the vault and is not time-weighted or subject to any minimum holding period. Repeated automated JIT extraction (economically rational and cheaply repeatable using flashloaned capital, since there is no price-impact cost to depositing/withdrawing at the prevailing ratio) results in continuous value transfer from real liquidity providers to opportunistic attackers, degrading the yield that the constant-product pool's fee model is designed to deliver to LPs — a direct loss of LP funds/revenue.

### Likelihood Explanation
The attack requires only unprivileged, permissionless instructions (`deposit`, `withdraw`, and observing/sequencing around any `swap_base_input`/`swap_base_output` call) reachable from a single attacker-controlled bundle of transactions with attacker-chosen accounts and amounts — no privileged signer, no non-default feature, and no off-chain assumption beyond ordinary MEV-style transaction sequencing (which is standard on Solana validators/leader slots). Because deposit/withdraw carry no slippage/price risk (they preserve the pool ratio), the attack is essentially risk-free and scales with available flashloaned/borrowed capital, making it a practical and repeatable strategy for any pool with meaningful swap volume relative to its liquidity depth.

### Recommendation
Introduce a mechanism that decouples "when fees accrue" from "instantaneous LP share," analogous to the bEth report's own recommendations:
- Enforce a minimum holding period (lock-up) between `deposit()` and a subsequent `withdraw()` for the same depositor/pool, or
- Accrue LP trading fees into a separate, time-weighted or per-epoch-snapshotted accounting bucket (similar to `protocol_fees_token_0/1`) rather than letting them anonymously inflate the raw vault balance that any depositor can instantly claim a pro-rata share of, or
- Charge a deposit/withdraw fee (as some CP-AMMs do) sized to offset the expected JIT extraction value, removing the risk-free nature of the sandwich.

### Proof of Concept
1. Attacker observes (or triggers via bundling) a large pending `swap_base_input` call against a target pool.
2. In the preceding transaction/instruction, attacker calls `deposit()` (`programs/cp-swap/src/instructions/deposit.rs:87-157`) with a large `lp_token_amount`, funded via flashloan, minting LP tokens proportional to the *pre-swap* vault ratio — no slippage risk since the ratio is preserved.
3. The victim's swap executes; `pool_state.update_fees()` records `protocol_fee`/`fund_fee`/`creator_fee` but the LP-fee remainder stays in `input_vault`'s raw balance, increasing `total_input_token_amount` for future ratio calculations.
4. Attacker calls `withdraw()` (`programs/cp-swap/src/instructions/withdraw.rs:99-202`) burning the same LP tokens, now redeemable for a higher amount of underlying tokens due to the fee-inflated vault balance, netting a profit equal to their pro-rata share of the swap's LP fee minus any token transfer fees.
5. Attacker repays the flashloan, retaining the skimmed fee as pure profit with no capital-at-risk exposure to the pool's price. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** programs/cp-swap/src/curve/calculator.rs (L95-143)
```rust
    pub fn swap_base_input(
        input_amount: u128,
        input_vault_amount: u128,
        output_vault_amount: u128,
        trade_fee_rate: u64,
        creator_fee_rate: u64,
        protocol_fee_rate: u64,
        fund_fee_rate: u64,
        is_creator_fee_on_input: bool,
    ) -> Option<SwapResult> {
        let mut creator_fee = 0;
        let trade_fee: u128;

        let input_amount_less_fees = if is_creator_fee_on_input {
            let total_fee = Fees::trading_fee(input_amount, trade_fee_rate + creator_fee_rate)?;
            creator_fee = Fees::split_creator_fee(total_fee, trade_fee_rate, creator_fee_rate)?;
            trade_fee = total_fee - creator_fee;
            input_amount.checked_sub(total_fee)?
        } else {
            trade_fee = Fees::trading_fee(input_amount, trade_fee_rate)?;
            input_amount.checked_sub(trade_fee)?
        };
        let protocol_fee = Fees::protocol_fee(trade_fee, protocol_fee_rate)?;
        let fund_fee = Fees::fund_fee(trade_fee, fund_fee_rate)?;

        let output_amount_swapped = ConstantProductCurve::swap_base_input_without_fees(
            input_amount_less_fees,
            input_vault_amount,
            output_vault_amount,
        );

        let output_amount = if is_creator_fee_on_input {
            output_amount_swapped
        } else {
            creator_fee = Fees::creator_fee(output_amount_swapped, creator_fee_rate)?;
            output_amount_swapped.checked_sub(creator_fee)?
        };

        Some(SwapResult {
            new_input_vault_amount: input_vault_amount.checked_add(input_amount_less_fees)?,
            new_output_vault_amount: output_vault_amount.checked_sub(output_amount_swapped)?,
            input_amount,
            output_amount,
            trade_fee,
            protocol_fee,
            fund_fee,
            creator_fee,
        })
    }
```

**File:** programs/cp-swap/src/states/pool.rs (L200-220)
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
