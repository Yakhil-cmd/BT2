### Title
Multi-BTC Token Reward Dilution via Depegged Asset Delegation - (File: `src/staking/staking.cairo`)

### Summary
The Starknet Staking protocol supports multiple BTC tokens simultaneously and normalizes all of them to 18 decimals for internal accounting. Because the reward distribution treats every normalized BTC unit as equivalent regardless of the token's actual market value, an attacker can delegate a large quantity of a depegged (cheaper) BTC token to dilute and steal STRK rewards that would otherwise accrue to delegators of higher-value BTC tokens.

### Finding Description
The protocol normalizes every BTC token amount to 18 decimals via `NormalizedAmountTrait::from_native_amount`: [1](#0-0) 

All active BTC tokens are then summed into a single `btc_curr_total_stake` in `get_total_staking_power_at_epoch`: [2](#0-1) 

During reward distribution in `calculate_staker_pools_rewards`, every BTC pool's share is computed as `pool_balance / btc_total_stake`, where `btc_total_stake` is that single aggregate figure: [3](#0-2) 

There is no price oracle or weighting mechanism that distinguishes between different BTC tokens by market value. One normalized unit of a depegged xBTC is treated identically to one normalized unit of a healthy yBTC.

### Impact Explanation
An attacker who acquires a large quantity of a depegged BTC token at a discount can delegate it to a pool and earn a disproportionate share of the epoch's `btc_total_rewards` (paid in STRK). Legitimate delegators of the non-depegged BTC token see their STRK reward share shrink in proportion to the attacker's inflated normalized balance. This constitutes **theft of unclaimed yield** (High impact).

Concretely: if xBTC trades at 0.9 yBTC and the attacker delegates 100 xBTC into a pool where 100 yBTC was already delegated, the attacker captures 50 % of all BTC-pool STRK rewards while having spent only 90 yBTC-equivalent of capital. The original yBTC delegators lose half their expected yield.

### Likelihood Explanation
Multiple BTC tokens (e.g., WBTC, FBTC, BTCB) are explicitly anticipated by the protocol. WBTC has historically depegged, and the original audit report cited in this prompt specifically calls out its instability. A sustained depeg of even a few percent over the `exit_wait_window` (default: one week) is sufficient for the attack to be profitable. No privileged access is required; any address can call `enter_delegation_pool` on a BTC pool. [4](#0-3) 

### Recommendation
1. **Introduce per-token reward buckets**: instead of aggregating all BTC tokens into one `btc_total_stake`, distribute rewards separately per token so that xBTC delegators only compete with other xBTC delegators.
2. **Alternatively, use a price oracle** to weight each BTC token's normalized balance by its current market value before aggregating into `btc_total_stake`.
3. **Enforce a minimum delegation lock-up** longer than the depeg window to reduce the profitability of short-lived depeg exploitation.

### Proof of Concept

**Setup**: Two BTC tokens are active — `xBTC` (8 decimals) and `yBTC` (8 decimals). Market rate: 1 xBTC = 0.9 yBTC. The staking contract holds 100 yBTC delegated across existing pools.

1. Attacker purchases 100 xBTC for the cost of 90 yBTC.
2. Attacker calls `enter_delegation_pool` on the xBTC pool, depositing 100 xBTC.
   - Normalized: `100 * 10^(18-8) = 100 * 10^10` units.
   - Existing yBTC normalized total: `100 * 10^10` units.
   - New `btc_total_stake`: `200 * 10^10` units.
3. At the next attestation, `calculate_staker_pools_rewards` computes:
   - xBTC pool share = `(100 * 10^10) / (200 * 10^10)` = **50 %** of `btc_total_rewards`.
   - yBTC pools share = **50 %** (down from 100 %).
4. Attacker waits for `exit_wait_window` (≥ 1 week), then calls `exit_delegation_pool_intent` followed by `exit_delegation_pool_action`, recovering 100 xBTC. [5](#0-4) 

5. **Net result**: Attacker spent 90 yBTC-equivalent, recovered 90 yBTC-equivalent (assuming depeg persists), and pocketed 50 % of all BTC-pool STRK rewards for the duration — rewards that belonged to the legitimate yBTC delegators.

The `TOKEN_MISMATCH` guard in `switch_staking_delegation_pool` prevents cross-token pool switching: [6](#0-5) 

but it does **not** prevent the reward dilution attack described above, since the attacker never needs to switch pools — they simply delegate cheap xBTC and claim STRK rewards.

### Citations

**File:** src/staking/objects.cairo (L51-54)
```text
    fn from_native_amount(amount: Amount, decimals: u8) -> NormalizedAmount {
        assert!(decimals >= 5 && decimals <= 18, "{}", GenericError::INVALID_TOKEN_DECIMALS);
        NormalizedAmount { amount_18_decimals: amount * 10_u128.pow(18 - decimals.into()) }
    }
```

**File:** src/staking/staking.cairo (L74-75)
```text
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
    pub(crate) const MAX_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: 12 * WEEK };
```

**File:** src/staking/staking.cairo (L1191-1196)
```text
            let to_token_address = self
                .staker_pool_info
                .entry(to_staker)
                .get_pool_token(pool_contract: to_pool)
                .expect_with_err(Error::DELEGATION_POOL_MISMATCH);
            assert!(token_address == to_token_address, "{}", Error::TOKEN_MISMATCH);
```

**File:** src/staking/staking.cairo (L1973-1984)
```text
                let (total_rewards, total_stake) = if token_address == STRK_TOKEN_ADDRESS {
                    (strk_total_rewards, strk_total_stake)
                } else {
                    (btc_total_rewards, btc_total_stake)
                };
                // Calculate rewards for this pool.
                let pool_rewards_including_commission = if total_stake.is_non_zero() {
                    mul_wide_and_div(
                        lhs: total_rewards,
                        rhs: pool_balance_curr_epoch.to_amount_18_decimals(),
                        div: total_stake.to_amount_18_decimals(),
                    )
```

**File:** src/staking/staking.cairo (L2420-2428)
```text
            let mut btc_curr_total_stake: NormalizedAmount = Zero::zero();
            for (token_address, active_status) in self.btc_tokens {
                if is_btc_active(:active_status, :epoch_id) {
                    let btc_total_stake_trace = self.tokens_total_stake_trace.entry(token_address);
                    btc_curr_total_stake +=
                        balance_at_epoch(trace: btc_total_stake_trace, :epoch_id);
                }
            }
            (strk_curr_total_stake, btc_curr_total_stake)
```

**File:** src/pool/pool.cairo (L182-199)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member = get_caller_address();
            assert!(
                self.pool_member_info.read(pool_member).is_none(), "{}", Error::POOL_MEMBER_EXISTS,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);
```
