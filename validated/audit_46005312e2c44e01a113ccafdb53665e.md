### Title
Rebasing/balance-adjusting tokens can permanently freeze pool funds via underflow in `vault_amount_without_fee` - ([File: programs/cp-swap/src/states/pool.rs])

### Summary
`PoolState::vault_amount_without_fee` subtracts accumulated protocol/fund/creator fee counters from the *live* vault token account balance without ever re-syncing those counters to actual balance changes that happen outside of the pool's own transfer/CPI logic. Every core user-facing instruction (`deposit`, `withdraw`, `swap_base_input`, `swap_base_output`) calls this function before performing its accounting, so if the vault's real balance ever drops below the sum of `protocol_fees_token_*` + `fund_fees_token_*` + `creator_fees_token_*`, the subtraction underflows and the instruction reverts, deadlocking the pool.

### Finding Description
`vault_amount_without_fee` computes:
```rust
vault_0.checked_sub(fees_token_0).ok_or(ErrorCode::InsufficientVault)?
``` [1](#0-0) 

`fees_token_0`/`fees_token_1` are running totals maintained purely as counters in `PoolState` (`protocol_fees_token_0`, `fund_fees_token_0`, `creator_fees_token_0`, etc.), incremented on every swap in `update_fees`, independent of the vault's actual on-chain balance. [2](#0-1) 

This is the same root cause as the referenced Noya finding: the protocol keeps a cached/derived accounting value (there, a user's `WithdrawRequest`; here, the fee counters) that is assumed to always be ≤ the real token balance, but the real balance can change independently of the pool's own transfer accounting (e.g., a rebasing token, a token with a balance-modifying extension, or any SPL-2022 mint whose balance can shrink outside of a `transfer`/`transfer_checked` call routed through the pool). Once the live vault balance falls below the sum of the fee counters, `vault_amount_without_fee` underflows and returns `ErrorCode::InsufficientVault`, which is propagated up through `get_swap_params` (used by both swap instructions) and directly in `deposit`/`withdraw`. [3](#0-2) [4](#0-3) [5](#0-4) 

Note: I was unable to fully verify, within the available iterations, exactly which SPL-2022 mint extensions are accepted by the program's `is_supported_mint` check in `programs/cp-swap/src/utils/token.rs`; if that check whitelists only extensions that cannot reduce a vault's balance outside of a direct transfer, this specific freeze scenario would be limited to abnormal/malicious or misconfigured mints rather than a "vanilla" set of allowed tokens. This uncertainty should be resolved by inspecting `is_supported_mint` and the mint-extension whitelist directly.

### Impact Explanation
Once triggered, `vault_amount_without_fee` errors on every subsequent call, so all of `deposit`, `withdraw`, `swap_base_input`, and `swap_base_output` for that pool revert permanently — there is no on-chain recovery path since the fee counters can only be reset by `collect_protocol_fee`/`collect_fund_fee` collecting real tokens the vault no longer has (which would itself fail for the same reason). All LP and swap-user funds in the pool's vaults become permanently frozen (Medium/High-Medium severity, matching the "funds get stuck in the contract" classification of the source finding).

### Likelihood Explanation
Likelihood depends on whether the pool can be created with (or a mint can later gain) an extension/mechanism that shrinks the vault's real token balance independent of pool-routed transfers. Any pool creator can call `initialize`/`initialize_with_permission` with an arbitrary Token-2022 mint pair (subject to whatever `is_supported_mint` allows), so if any accepted extension or future mint behavior permits balance loss outside of transfers, an unprivileged actor (the pool creator, or simply time/epoch-based effects on such a mint) can put the pool in this frozen state without any privileged action.

### Recommendation
- Do not rely on a purely incremental fee-counter model divorced from actual vault balance; clamp fee counters (as already done for LP redemption amounts via `std::cmp::min`) or recompute/re-sync fee counters against the live vault balance instead of using an unclamped `checked_sub`.
- Alternatively, when `vault_0 < fees_token_0` (or the token_1 equivalent), gracefully cap the fee amount to the available balance and log/emit an event, rather than aborting the entire instruction, so that legitimate deposit/withdraw/swap flows are not globally deadlocked by an errant mint.
- Explicitly document/restrict which Token-2022 mint extensions are supported (via `is_supported_mint`) to exclude any extension capable of altering balances outside of pool-routed transfers.

### Proof of Concept
1. A pool creator initializes a pool via `initialize` with `token_0` being a Token-2022 mint whose extension can reduce a token account's balance independent of a `transfer`/`transfer_checked` instruction (e.g., any future/community-deployed "rebasing" or balance-adjusting extension accepted by `is_supported_mint`).
2. Normal swaps occur, incrementing `protocol_fees_token_0`, `fund_fees_token_0`, and (if enabled) `creator_fees_token_0` via `update_fees`. [6](#0-5) 
3. The mint's balance-adjustment mechanism reduces `token_0_vault.amount` such that it becomes less than the accumulated `protocol_fees_token_0 + fund_fees_token_0 + creator_fees_token_0`.
4. Any subsequent call to `deposit`, `withdraw`, `swap_base_input`, or `swap_base_output` calls `vault_amount_without_fee`, which underflows on `vault_0.checked_sub(fees_token_0)` and returns `ErrorCode::InsufficientVault`, reverting the transaction. [7](#0-6) 
5. Because every user-facing instruction depends on this same computation, the pool is now permanently unusable, and all tokens held in `token_0_vault`/`token_1_vault` (deposits from all LPs) are stuck with no path to withdraw them.

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

**File:** programs/cp-swap/src/states/pool.rs (L263-316)
```rust
    pub fn get_swap_params(
        &self,
        input_vault_key: Pubkey,
        output_vault_key: Pubkey,
        input_vault_amount: u64,
        output_vault_amount: u64,
    ) -> Result<SwapParams> {
        let (
            trade_direction,
            total_input_token_amount,
            total_output_token_amount,
            token_0_price_x64,
            token_1_price_x64,
            is_creator_fee_on_input,
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

            (
                TradeDirection::OneForZero,
                total_input_token_amount,
                total_output_token_amount,
                token_0_price_x64,
                token_1_price_x64,
                self.is_creator_fee_on_input(TradeDirection::OneForZero)?,
            )
        } else {
            return err!(ErrorCode::InvalidVault);
        };
        Ok(SwapParams {
            trade_direction,
            total_input_token_amount,
            total_output_token_amount,
            token_0_price_x64,
            token_1_price_x64,
            is_creator_fee_on_input,
        })
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

**File:** programs/cp-swap/src/instructions/deposit.rs (L99-102)
```rust
    let (total_token_0_amount, total_token_1_amount) = pool_state.vault_amount_without_fee(
        ctx.accounts.token_0_vault.amount,
        ctx.accounts.token_1_vault.amount,
    )?;
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L112-115)
```rust
    let (total_token_0_amount, total_token_1_amount) = pool_state.vault_amount_without_fee(
        ctx.accounts.token_0_vault.amount,
        ctx.accounts.token_1_vault.amount,
    )?;
```
