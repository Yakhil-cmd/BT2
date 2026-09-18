### Title
Unbounded fee accumulators (`protocol_fees_token_*`, `fund_fees_token_*`, `creator_fees_token_*`) can overflow `u64` and permanently DoS `swap`, `deposit`, and `withdraw` - ([File: programs/cp-swap/src/states/pool.rs])

### Summary
`PoolState::update_fees` accumulates protocol/fund/creator fees into `u64` fields on every swap using `.checked_add(...).unwrap()`, with no upper bound, and the only way to reduce these accumulators is a privileged `collect_protocol_fee` / `collect_fund_fee` (or `collect_creator_fee`) call. `vault_amount_without_fee`, which is invoked by `deposit`, `withdraw`, `swap_base_input`, and `swap_base_output` on every call, sums these three growing accumulators together. As the accumulators grow without bound (via unprivileged, attacker-driven round-trip swapping) and are not collected in time, the summation/`unwrap()` can overflow, causing every subsequent swap/deposit/withdraw on the pool to revert — a permanent freeze of pool funds until an admin/fund-owner collects fees to reduce the accumulators (if even possible before overflow blocks the transaction entirely).

### Finding Description
`PoolState::update_fees` adds the newly computed protocol/fund/creator fee to the corresponding `u64` accumulator field using `unwrap()`-based (panicking) arithmetic, called from both swap paths on every trade: [1](#0-0) 

These accumulators are only ever incremented by `update_fees`; they are decremented only through the admin/fund-owner-only `collect_protocol_fee` and `collect_fund_fee` instructions: [2](#0-1) [3](#0-2) 

Every core pool operation that touches vault balances — `deposit`, `withdraw`, `swap_base_input`, `swap_base_output` — calls `vault_amount_without_fee`, which sums all three fee accumulators (`protocol_fees_token_x + fund_fees_token_x + creator_fees_token_x`) before subtracting them from the raw vault balance: [4](#0-3) 

This is called directly from `withdraw`: [5](#0-4) 

and via `get_swap_params` in both swap instructions.

This mirrors the reported bug class exactly: a monotonically growing, unprivileged-triggered accumulator (`ohmRemoved` in the original report; here `protocol_fees_token_*`/`fund_fees_token_*`/`creator_fees_token_*`) feeds into arithmetic (`LIMIT + ohmRemoved` in the original; `a + b + c` and `.unwrap()` additions here) that can overflow and cause the containing function to revert, blocking otherwise-valid operations. Just as in the original report, the issue is mitigated only by privileged action (there: lowering `LIMIT`; here: an admin/fund owner collecting fees), which does not eliminate the underlying flaw that an unprivileged actor can drive the state toward the failure condition.

### Impact Explanation
Once the summed fee accumulators for a token approach `u64::MAX`, any call to `vault_amount_without_fee` — invoked by `deposit`, `withdraw`, `swap_base_input`, and `swap_base_output` — will either panic (`unwrap()` on overflow in `update_fees`) or deterministically return `ErrorCode::MathOverflow` (in `vault_amount_without_fee` itself). Because `withdraw` also depends on this function, LP holders would be unable to withdraw their underlying tokens from the pool, and no further swaps could occur, constituting a permanent freeze of pool funds. This matches the required impact bar of permanent freezing of user/LP funds.

### Likelihood Explanation
Reaching this state requires driving one or more `u64` fee accumulators (bounded in practice by cumulative trading volume × fee rate, not by a single transaction) to near `u64::MAX` through many repeated swap transactions — feasible for a determined, well-resourced attacker performing sustained round-trip trading on a pool with high fee rates and low-decimal tokens, especially if the pool's fund/protocol fee collectors are inactive. This is a slow, cumulative, unprivileged attack path rather than a single-transaction exploit, so likelihood is lower than an immediately-triggerable bug, consistent with the "Medium" classification of the analogous original finding (mitigable only via active admin intervention).

### Recommendation
- Bound the fee accumulators or split them into a running total that is periodically checkpointed/reset upon collection so a single field cannot approach `u64::MAX`.
- Replace `.unwrap()` calls in `update_fees` with `checked_add(...).ok_or(ErrorCode::MathOverflow)?` (as already done in `vault_amount_without_fee`) so failures are explicit `Result` errors rather than panics, and add monitoring/alerting so operators collect fees well before any accumulator nears the overflow threshold.
- Consider computing `vault_amount_without_fee` using saturating arithmetic combined with `min()` guards, ensuring that even if fee bookkeeping approaches extreme values, core `withdraw`/`swap` paths degrade gracefully rather than reverting outright.

### Proof of Concept
1. Attacker repeatedly performs `swap_base_input`/`swap_base_output` round-trips (A→B→A) on a pool with a non-trivial fee rate, causing `PoolState::update_fees` to keep incrementing `protocol_fees_token_0/1`, `fund_fees_token_0/1`, and/or `creator_fees_token_0/1` [6](#0-5) .
2. If the pool's fee collectors (privileged `collect_protocol_fee`/`collect_fund_fee`) do not withdraw fees fast enough relative to trading volume, the sum of accumulators for a token approaches `u64::MAX`.
3. The next call to `vault_amount_without_fee` (from `deposit`, `withdraw`, or either swap instruction) computes `protocol_fees_token_x.checked_add(fund_fees_token_x)?.checked_add(creator_fees_token_x)?`, which overflows and returns `ErrorCode::MathOverflow` [7](#0-6) , or `update_fees`'s `.unwrap()` panics on the next swap before that point is even reached.
4. From this point forward, all `deposit`, `withdraw`, `swap_base_input`, and `swap_base_output` calls on the pool revert, freezing LP funds until an admin intervenes (and even then, intervention may not be possible if the panic occurs before collection can be executed).

### Citations

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

**File:** programs/cp-swap/src/instructions/admin/collect_protocol_fee.rs (L74-98)
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

**File:** programs/cp-swap/src/instructions/withdraw.rs (L112-115)
```rust
    let (total_token_0_amount, total_token_1_amount) = pool_state.vault_amount_without_fee(
        ctx.accounts.token_0_vault.amount,
        ctx.accounts.token_1_vault.amount,
    )?;
```
