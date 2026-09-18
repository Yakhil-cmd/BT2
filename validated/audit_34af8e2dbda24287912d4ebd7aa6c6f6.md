### Title
Unchecked division-by-zero panic in `token_price_x32` permanently bricks swap functionality once a vault's tradable balance reaches zero - ([File: programs/cp-swap/src/states/pool.rs])

### Summary
`PoolState::token_price_x32` performs raw integer division with no zero-check on either divisor, and it is invoked unconditionally on every `swap_base_input`/`swap_base_output` call via `get_swap_params`. If either side's tradable balance (`vault_amount - accumulated_fees`) reaches exactly zero, the division panics, aborting not just that transaction but every future swap transaction that touches the pool in that state — a persistent denial-of-service on the pool's swap path, analogous in bug-class to CVE-2017-3450 (an easily triggerable, unauthenticated crash/hang caused by unvalidated input reaching an unguarded numeric operation).

### Finding Description
`token_price_x32` computes: [1](#0-0) 

Unlike every other arithmetic path in `pool.rs` — which consistently uses `checked_add`/`checked_sub`/`checked_mul` with `ErrorCode::MathOverflow` or `ErrorCode::InsufficientVault` fallbacks (see `vault_amount_without_fee`) — this function divides directly by `token_0_amount` and `token_1_amount` without any zero-guard: [2](#0-1) 

`token_price_x32` is called unconditionally from `get_swap_params`, which is itself invoked at the start of both `swap_base_input` and `swap_base_output`, before any of the fee/slippage logic runs: [3](#0-2) [4](#0-3) [5](#0-4) 

If the tradable balance on either side of the pool (raw vault amount minus `protocol_fees + fund_fees + creator_fees` for that mint) is driven to exactly zero — a state that a low-liquidity pool can reach through a sequence of unprivileged, attacker-chosen `swap_base_input`/`swap_base_output` calls that progressively withdraw nearly all of one token while fees continue to accrue on the other — any subsequent swap attempt in either direction computes `x / 0` and panics inside the Solana runtime for that instruction. Because the check happens unconditionally on every swap call (regardless of the specific amounts requested by the new caller), the pool becomes permanently unable to process any swap once this state is reached, not merely the single triggering transaction.

### Impact Explanation
This is not simple theft, but it does meet the "permanent freezing" bar: once the zero-balance condition is reached, `swap_base_input` and `swap_base_output` become permanently unusable for that pool for all subsequent unprivileged callers, since the panic occurs deterministically before any swap-specific validation runs. LPs' capital remains locked in a pool that can no longer be traded against (a persistent, unrecoverable DOS of the AMM's core function), which is directly analogous to the "hang or repeatable crash" impact class described in CVE-2017-3450.

### Likelihood Explanation
Reaching an exact zero-tradable-balance state via normal constant-product swaps is difficult because the `ConstantProductCurve` math (`checked_sub` on `output_vault_amount - output_amount`) asymptotically approaches but does not trivially reach a full drain in a single swap. However, over many attacker-controlled swaps in a thinly-liquidity pool (especially one seeded with minimal initial liquidity, which any unprivileged user can create via `initialize`), or through interactions with fee accrual, an attacker can plausibly engineer the exact-zero condition. I was not able to fully verify from the available code paths whether the curve math strictly forbids `total_output_token_amount` (post-fee) from ever hitting exactly zero across compounded swaps, or whether such compounding is realistically achievable; this remains uncertain and would need targeted testing/fuzzing to confirm exploitability with concrete numbers.

### Recommendation
Add explicit zero-checks in `token_price_x32` and return `ErrorCode::ZeroTradingTokens` (or similar) instead of dividing unconditionally, consistent with the checked-arithmetic pattern used elsewhere in `pool.rs`:
```rust
pub fn token_price_x32(&self, vault_0: u64, vault_1: u64) -> Result<(u128, u128)> {
    let (token_0_amount, token_1_amount) = self.vault_amount_without_fee(vault_0, vault_1)?;
    require!(token_0_amount > 0 && token_1_amount > 0, ErrorCode::ZeroTradingTokens);
    Ok((
        (token_1_amount as u128).checked_mul(Q32 as u128).ok_or(ErrorCode::MathOverflow)? / token_0_amount as u128,
        (token_0_amount as u128).checked_mul(Q32 as u128).ok_or(ErrorCode::MathOverflow)? / token_1_amount as u128,
    ))
}
```

### Proof of Concept
1. Attacker (or anyone) calls `initialize` to create a pool with minimal initial liquidity via [6](#0-5) .
2. Attacker repeatedly calls `swap_base_input`/`swap_base_output` with self-chosen amounts, progressively draining one side of the pool toward the point where `vault_amount == accumulated_fees` for that mint.
3. Once `vault_amount_without_fee` returns `0` for one side, the very next `get_swap_params` call (triggered by any user's swap in either direction) executes `token_1_amount as u128 * Q32 as u128 / token_0_amount as u128` (or the symmetric division) with a zero divisor, panicking inside [7](#0-6) .
4. All subsequent swap transactions against this pool panic identically, permanently disabling the pool's swap functionality while leaving LP funds locked (withdraw is unaffected, but the AMM's core trading function is bricked).

### Citations

**File:** programs/cp-swap/src/states/pool.rs (L134-178)
```rust
    pub fn initialize(
        &mut self,
        auth_bump: u8,
        lp_supply: u64,
        open_time: u64,
        pool_creator: Pubkey,
        amm_config: Pubkey,
        token_0_vault: Pubkey,
        token_1_vault: Pubkey,
        token_0_mint: &InterfaceAccount<Mint>,
        token_1_mint: &InterfaceAccount<Mint>,
        lp_mint: Pubkey,
        lp_mint_decimals: u8,
        observation_key: Pubkey,
        creator_fee_on: CreatorFeeOn,
        enable_creator_fee: bool,
    ) {
        self.amm_config = amm_config.key();
        self.pool_creator = pool_creator.key();
        self.token_0_vault = token_0_vault;
        self.token_1_vault = token_1_vault;
        self.lp_mint = lp_mint.key();
        self.token_0_mint = token_0_mint.key();
        self.token_1_mint = token_1_mint.key();
        self.token_0_program = *token_0_mint.to_account_info().owner;
        self.token_1_program = *token_1_mint.to_account_info().owner;
        self.observation_key = observation_key;
        self.auth_bump = auth_bump;
        self.lp_mint_decimals = lp_mint_decimals;
        self.mint_0_decimals = token_0_mint.decimals;
        self.mint_1_decimals = token_1_mint.decimals;
        self.lp_supply = lp_supply;
        self.protocol_fees_token_0 = 0;
        self.protocol_fees_token_1 = 0;
        self.fund_fees_token_0 = 0;
        self.fund_fees_token_1 = 0;
        self.open_time = open_time;
        self.recent_epoch = Clock::get().unwrap().epoch;
        self.creator_fee_on = creator_fee_on.to_u8();
        self.enable_creator_fee = enable_creator_fee;
        self.padding1 = [0u8; 6];
        self.creator_fees_token_0 = 0;
        self.creator_fees_token_1 = 0;
        self.padding = [0u64; 28];
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

**File:** programs/cp-swap/src/states/pool.rs (L263-296)
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
