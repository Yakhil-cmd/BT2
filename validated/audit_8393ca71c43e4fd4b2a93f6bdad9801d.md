### Title
Permanent DoS of `swap_base_input`/`swap_base_output` via unrecoverable `MathOverflow` in `ObservationState::update` - (File: `programs/cp-swap/src/states/oracle.rs`)

### Summary
`Observation::update` computes the price delta to accumulate into the TWAP oracle using `checked_mul` on a `u128` price times the elapsed time, and propagates any overflow as a hard `Err(ErrorCode::MathOverflow)` via `?` into the swap instructions. [1](#0-0)  Because the routine only advances `last_update_timestamp` on success, a single overflowing update permanently blocks all future swaps on that pool, since elapsed time can only grow larger from then on. [2](#0-1) 

### Finding Description
`swap_base_input` and `swap_base_output` both call `ctx.accounts.observation_state.load_mut()?.update(...)` unconditionally at the end of the swap, after the token transfers have already been queued, and propagate any error with `?`, which aborts the whole atomic transaction. [3](#0-2) 

Inside `update`, the price passed in (`token_0_price_x64`/`token_1_price_x64`, actually a Q32.32-style fixed point value computed as `token_1_amount * Q32 / token_0_amount`) is multiplied by `time_since_last_update` (elapsed seconds since the last successful update) using `checked_mul`, and any overflow returns `ErrorCode::MathOverflow`: [4](#0-3) 

Unlike the referenced `wrapping_add` used for accumulating into the cumulative field (which correctly tolerates rollover), the *delta* computation is **not** allowed to overflow — it reverts. Crucially, `self.last_update_timestamp` is only updated at the very end of the function, after the (possibly failing) `checked_mul` calls: [5](#0-4) 

This means that once a single call to `update` fails due to overflow, `last_update_timestamp` is never advanced. Every subsequent swap attempt computes `time_since_last_update = block_timestamp.saturating_sub(self.last_update_timestamp)`, which only grows larger over time, guaranteeing the `checked_mul` overflow persists (and worsens) forever. Since `swap_base_input`/`swap_base_output` are the only paths reaching this instruction and they both unconditionally call `.update()?` before returning `Ok(())`, once triggered, the pool's swap functionality is permanently and irrecoverably broken — a direct analog to the JalaSwap `_update` overflow-revert issue, except here the failure mode is `checked_mul` reverting instead of an unchecked add/sub reverting under Solidity ≥0.8.

The price value that can be pushed to a level enabling overflow is `token_1_amount * 2^32 / token_0_amount`, computed in `PoolState::token_price_x32`: [6](#0-5) 

An attacker/LP-controlled pool state where one vault balance is driven down to a very small value (e.g., 1) while the other approaches `u64::MAX` produces a price on the order of `~1.8e19 * 2^32 ≈ 7.7e28`. Multiplying this by an elapsed time on the order of years (`~1e8`–`1e10` seconds, achievable well within realistic pool lifetimes, especially if the pool goes untouched for an extended period after the reserve ratio becomes extreme) can exceed `u128::MAX` (~3.4e38), triggering the unrecoverable overflow.

### Impact Explanation
Once triggered, every future call to `swap_base_input` and `swap_base_output` on the affected pool reverts, permanently freezing the pool's core trading functionality and any user/LP funds that depend on being able to swap (e.g., LPs relying on continued trading to earn fees, or funds that require a swap path to be withdrawn/rebalanced). This matches the "permanent freezing of user or LP funds" / permanent DoS category validated as Medium severity in the referenced Sherlock report, since it is a low-probability-but-certain event (occurs once elapsed time × extreme price ratio crosses the u128 boundary) with high impact (permanent breakage of swap instructions for the pool).

### Likelihood Explanation
Reaching an extreme reserve ratio (one vault near `1` unit, the other near `u64::MAX`) is possible in principle within the constant-product AMM if a pool is created/drained toward such a skewed state and then left untouched for a long period; the exact time-to-overflow depends heavily on the specific price ratio achieved and is on the order of years to over a century in the extreme case, mirroring the same "far future, but 100% eventual" characterization from the original Sherlock M-3 finding, which was ultimately judged Medium severity despite requiring an extended timeframe.

### Recommendation
Make the delta accumulation in `Observation::update` intentionally tolerate overflow (mirroring the `wrapping_add` already used for the cumulative accumulator), e.g. use `wrapping_mul` for `token_0_price_x32.wrapping_mul(time_since_last_update.into())` instead of `checked_mul().ok_or(ErrorCode::MathOverflow)?`, so that the oracle can never brick swap functionality regardless of price ratio or elapsed time, consistent with how UniswapV2-style oracles are designed to safely wrap.

### Proof of Concept
Conceptually:
1. Create a pool and, through swaps, drive one vault's `vault_amount_without_fee` down to a very small value (e.g. 1) while the other vault holds a very large balance (approaching `u64::MAX`), producing an extreme `token_price_x32` per `PoolState::token_price_x32`.
2. Allow enough real time to elapse (so `time_since_last_update` in `Observation::update` grows sufficiently) without any swap on the pool (permissionless — no one is required to swap in the interim).
3. Call `swap_base_input` (or `swap_base_output`) once more; `checked_mul` in `Observation::update` overflows and returns `Err(ErrorCode::MathOverflow)`, which propagates via `?` and reverts the whole transaction, atomically undoing the token transfers as well.
4. Because `last_update_timestamp` was not advanced on the failed call, every subsequent swap attempt computes an even larger `time_since_last_update`, so the overflow condition can never resolve itself — the pool's swap instructions are permanently DoS'd. [7](#0-6) [3](#0-2)

### Citations

**File:** programs/cp-swap/src/states/oracle.rs (L78-141)
```rust
    pub fn update(
        &mut self,
        block_timestamp: u64,
        token_0_price_x32: u128,
        token_1_price_x32: u128,
    ) -> Result<()> {
        let observation_index = self.observation_index;
        if !self.initialized {
            // skip the pool init price
            self.initialized = true;
            self.observations[observation_index as usize].block_timestamp = block_timestamp;
            self.observations[observation_index as usize].cumulative_token_0_price_x32 = 0;
            self.observations[observation_index as usize].cumulative_token_1_price_x32 = 0;
            self.last_update_timestamp = block_timestamp;
            return Ok(());
        }
        let last_observation = self.observations[observation_index as usize];
        let next_observation_index = if observation_index as usize == OBSERVATION_NUM - 1 {
            0
        } else {
            observation_index + 1
        };
        // Ensure last_update_timestamp is set for legacy accounts
        if self.last_update_timestamp == 0 {
            self.last_update_timestamp = last_observation.block_timestamp;
        }
        let time_since_last_observation =
            block_timestamp.saturating_sub(last_observation.block_timestamp);
        // Accumulate using last known price over the elapsed time
        let time_since_last_update = block_timestamp.saturating_sub(self.last_update_timestamp);
        if time_since_last_update == 0 || time_since_last_observation == 0 {
            return Ok(());
        }
        let delta_token_0_price_x32 = token_0_price_x32
            .checked_mul(time_since_last_update.into())
            .ok_or(ErrorCode::MathOverflow)?;
        let delta_token_1_price_x32 = token_1_price_x32
            .checked_mul(time_since_last_update.into())
            .ok_or(ErrorCode::MathOverflow)?;
        if time_since_last_observation < OBSERVATION_UPDATE_DURATION_DEFAULT {
            self.observations[observation_index as usize].cumulative_token_0_price_x32 =
                last_observation
                    .cumulative_token_0_price_x32
                    .wrapping_add(delta_token_0_price_x32);
            self.observations[observation_index as usize].cumulative_token_1_price_x32 =
                last_observation
                    .cumulative_token_1_price_x32
                    .wrapping_add(delta_token_1_price_x32);
        } else {
            self.observations[next_observation_index as usize].block_timestamp = block_timestamp;
            // cumulative_token_price_x32 only occupies the first 64 bits, and the remaining 64 bits are used to store overflow data
            self.observations[next_observation_index as usize].cumulative_token_0_price_x32 =
                last_observation
                    .cumulative_token_0_price_x32
                    .wrapping_add(delta_token_0_price_x32);
            self.observations[next_observation_index as usize].cumulative_token_1_price_x32 =
                last_observation
                    .cumulative_token_1_price_x32
                    .wrapping_add(delta_token_1_price_x32);
            self.observation_index = next_observation_index;
        }
        self.last_update_timestamp = block_timestamp;
        Ok(())
    }
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L203-208)
```rust
    // update the previous price to the observation
    ctx.accounts.observation_state.load_mut()?.update(
        oracle::block_timestamp(),
        token_0_price_x64,
        token_1_price_x64,
    )?;
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
