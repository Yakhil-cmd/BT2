### Title
Unbounded fee accumulator overflow permanently halts all swaps for a pool - ([File: programs/cp-swap/src/states/pool.rs])

### Summary
`PoolState::update_fees`, called from both `swap_base_input` and `swap_base_output` on every trade, accumulates protocol/fund/creator fees into `u64` fields using `.checked_add(...).unwrap()`. These accumulators are monotonically increasing and can only be reduced by a separate, permissioned collection instruction. If cumulative fees for a token side reach `u64::MAX`, the `unwrap()` panics and every subsequent swap that routes fees to that token side reverts, permanently freezing swap functionality (and the funds locked in the pool for that trade direction) unless the owner collects fees before the threshold is hit.

### Finding Description
On every swap, `update_fees` adds the newly computed `protocol_fee`, `fund_fee`, and `creator_fee` to the pool's persistent `u64` counters using `.unwrap()` rather than a graceful error path: [1](#0-0) 

These counters (`protocol_fees_token_0/1`, `fund_fees_token_0/1`, `creator_fees_token_0/1`) are stored in `PoolState` as `u64` and are only ever decremented by the permissioned `collect_protocol_fee`, `collect_fund_fee`, and `collect_creator_fee` instructions: [2](#0-1) [3](#0-2) 

`update_fees` is unconditionally invoked from the permissionless swap entry points before the token transfers occur: [4](#0-3) [5](#0-4) 

Because `swap_base_input`/`swap_base_output` are reachable by any unprivileged user with attacker-chosen `amount_in`/`amount_out`, an attacker can create a pool with a self-minted, high-supply token (`initialize`), seed it with large liquidity, and then repeatedly execute large swaps to accrue fee amounts that sum toward `u64::MAX` on the relevant side's counter. Once the addition would overflow, the `.unwrap()` panics and the instruction reverts — but critically, this happens *inside* the swap path that every future trader must go through, so once the accumulator is near the ceiling, all subsequent swaps in that direction fail deterministically until the owner separately calls the collection instruction to zero it out.

This closely mirrors the reported bug class: a value computed deep in a hot, permissionless-reachable code path (fee accrual here; interest rate there) can grow to a magnitude that trips a hard failure (`unwrap()`/`require`) baked into the primary user-facing function (`update_fees` inside every swap, vs. `_updateInterest` inside every lending operation), with no dedicated guard clamping the value to a safe range before the addition.

### Impact Explanation
If triggered, every swap that would add to the overflowed fee counter fails, denying LPs and traders the ability to swap through the pool, and effectively freezes further trading against that pool until an owner/admin proactively collects fees down. This is a denial-of-service on core AMM functionality and, unlike deposit/withdraw, has no user-level bypass. LP and trader funds already in the vaults remain deposit/withdrawable independent of `update_fees` (deposit/withdraw don't call it), so the impact is scoped to blocking `swap_base_input`/`swap_base_output`, not full fund loss — but it is a persistent freeze of a core, permissionless function reachable purely from swap activity.

### Likelihood Explanation
Likelihood is low-to-moderate in practice: fee rates are bounded fractions of `amount_in`/`amount_out` (both capped at `u64::MAX`), so reaching a cumulative sum near `u64::MAX` on a single fee counter requires either an extraordinarily large number of large-notional swaps, or an attacker deliberately engineering a self-created pool with a high-supply token and looping large swaps to force the accumulator toward the ceiling before the owner ever calls the collection instructions. It is fully attacker-controlled for pools created by the attacker (own mint, own liquidity, own swap volume) and requires no privileged signer, only repeated calls to `initialize`/`deposit`/`swap_base_input`.

### Recommendation
- Replace `.checked_add(...).unwrap()` in `PoolState::update_fees` with proper error propagation (`.ok_or(ErrorCode::MathOverflow)?`) so an overflow returns a clean error instead of a panic, and does not lock the fee-accumulation path itself once close to the ceiling.
- Consider capping or auto-flushing fee accumulators (e.g., forcing a partial fee credit/emit-and-truncate) rather than relying solely on manual, permissioned collection to prevent the counters from approaching `u64::MAX`.
- Optionally track fee totals in wider integer types or emit fees to LP-claimable state that resets frequently, decoupling continuous swap execution from the size of any single persistent accumulator.

### Proof of Concept
1. Attacker calls `initialize` (permissionless) with a self-controlled mint that they can mint up to `u64::MAX` supply, and deposits large liquidity via `deposit`.
2. Attacker repeatedly calls `swap_base_input`/`swap_base_output` with large `amount_in` values, driving `protocol_fee`/`fund_fee`/`creator_fee` amounts that are proportional to `amount_in` (per `Fees::trading_fee`, `Fees::protocol_fee`, etc., in `programs/cp-swap/src/curve/fees.rs`) into the pool's `protocol_fees_token_0` (or `_1`) counter via repeated `update_fees` calls: [6](#0-5) 
3. Once cumulative `protocol_fees_token_0` (or the relevant counter) is one addition away from `u64::MAX`, the next swap in that direction triggers `.checked_add(protocol_fee).unwrap()` to panic, reverting the transaction — and every subsequent swap attempting to add to that same counter reverts identically, since the counter's value never decreases without an explicit `collect_protocol_fee`/`collect_fund_fee`/`collect_creator_fee` call by the pool's `protocol_owner`.
4. Until the owner submits the corresponding `collect_*_fee` transaction to reduce the counter, all swaps that route fees to the affected token side are permanently denied for any user of that pool.

**Note on confidence:** I was not able to load `programs/cp-swap/src/states/config.rs` fee-rate bounds or `collect_creator_fee.rs` in full within the available searches, so I cannot cite the exact maximum configurable `trade_fee_rate`/`protocol_fee_rate` values, which affects how many/how-large swaps would be needed in practice to approach the `u64::MAX` threshold. This limits precise quantification of likelihood but does not affect the validity of the root-cause code path identified above.

### Citations

**File:** programs/cp-swap/src/states/pool.rs (L104-128)
```rust
    /// True circulating supply without burns and lock ups
    pub lp_supply: u64,
    /// The amounts of token_0 and token_1 that are owed to the liquidity provider.
    pub protocol_fees_token_0: u64,
    pub protocol_fees_token_1: u64,

    pub fund_fees_token_0: u64,
    pub fund_fees_token_1: u64,

    /// The timestamp allowed for swap in the pool.
    pub open_time: u64,
    /// recent epoch
    pub recent_epoch: u64,

    /// Creator fee collect mode
    /// 0: both token_0 and token_1 can be used as trade fees. It depends on what the input token is when swapping
    /// 1: only token_0 as trade fee
    /// 2: only token_1 as trade fee
    pub creator_fee_on: u8,
    pub enable_creator_fee: bool,
    pub padding1: [u8; 6],
    pub creator_fees_token_0: u64,
    pub creator_fees_token_1: u64,
    /// padding for future updates
    pub padding: [u64; 28],
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

**File:** programs/cp-swap/src/instructions/admin/collect_fund_fee.rs (L82-90)
```rust
        let mut pool_state = ctx.accounts.pool_state.load_mut()?;
        amount_0 = amount_0_requested.min(pool_state.fund_fees_token_0);
        amount_1 = amount_1_requested.min(pool_state.fund_fees_token_1);

        pool_state.fund_fees_token_0 = pool_state.fund_fees_token_0.checked_sub(amount_0).unwrap();
        pool_state.fund_fees_token_1 = pool_state.fund_fees_token_1.checked_sub(amount_1).unwrap();
        auth_bump = pool_state.auth_bump;
        pool_state.recent_epoch = Clock::get()?.epoch;
    }
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

**File:** programs/cp-swap/src/instructions/swap_base_output.rs (L100-105)
```rust
    pool_state.update_fees(
        u64::try_from(result.protocol_fee).unwrap(),
        u64::try_from(result.fund_fee).unwrap(),
        u64::try_from(result.creator_fee).unwrap(),
        trade_direction,
    )?;
```
