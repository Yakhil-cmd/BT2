### Title
Staker's Own Balance Passed as Total Network Stake in `update_rewards`, Causing Inflated Reward Distribution in Consensus Phase — (File: `src/staking/staking.cairo`)

---

### Summary

In the consensus-phase reward path (`update_rewards`), the staker's own STRK/BTC balance is passed as the `strk_total_stake` / `btc_total_stake` denominator to `_update_rewards`. The pre-consensus path (`update_rewards_from_attestation_contract`) correctly passes the total network staking power. Because `_update_rewards` uses these values as the denominator when computing each staker's proportional share, the consensus path causes every calling staker to be treated as if they hold 100 % of the network stake, receiving the full block reward instead of their proportional slice.

---

### Finding Description

**Pre-consensus path** (`update_rewards_from_attestation_contract`, lines 1406–1422):

```cairo
let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
self._update_rewards(
    ...
    :strk_total_stake,   // ← total network staking power  ✓
    :btc_total_stake,
    ...
);
```

**Consensus path** (`update_rewards`, lines 1474–1506):

```cairo
let (staker_total_strk_balance, staker_total_btc_balance) = self
    .get_staker_total_strk_btc_balance_at_epoch(
        :staker_address, :staker_pool_info, epoch_id: curr_epoch,
    );
// ...
self._update_rewards(
    ...
    strk_total_stake: staker_total_strk_balance,  // ← staker's OWN balance  ✗
    btc_total_stake:  staker_total_btc_balance,   // ← staker's OWN balance  ✗
    ...
);
```

The helper `calculate_staker_total_staking_power` (utils.cairo lines 124–147) confirms how these parameters are consumed — as the denominator:

```cairo
let strk_staking_power = mul_wide_and_div(
    lhs: staker_strk_total_amount.to_amount_18_decimals(),
    rhs: STRK_WEIGHT_FACTOR,
    div: strk_total_stake.to_amount_18_decimals(),   // ← denominator
).unwrap();
```

When `strk_total_stake == staker_strk_total_amount` (the staker's own balance), the division yields 1, and the staker is credited `STRK_WEIGHT_FACTOR` worth of staking power — the maximum possible — regardless of their actual network share. Consequently the staker receives the entire `strk_block_rewards` for that block.

The `last_reward_block` guard (line 1454–1458) serialises calls: only one staker can update rewards per block. The first caller each block therefore captures 100 % of that block's reward, starving every other staker.

---

### Impact Explanation

**Theft of unclaimed yield (High).**

A staker holding, say, 1 % of total stake calls `update_rewards` first in a block. Because `strk_total_stake` equals their own balance, the reward formula resolves to `block_rewards × own_balance / own_balance = block_rewards`. They receive the full block reward. All other stakers receive nothing for that block. Repeated across every block, a well-positioned staker can drain the reward pool at the expense of all other participants.

---

### Likelihood Explanation

**High.** `update_rewards` is a public, permissionless function (only `general_prerequisites` — unpaused + non-zero caller — is checked). Any staker can call it at the start of each block. The consensus phase is the production reward path once `consensus_rewards_first_epoch` is set. The bug fires on every single block in that phase.

---

### Recommendation

In `update_rewards`, fetch the total network staking power before calling `_update_rewards`, mirroring the pre-consensus path:

```cairo
// Replace:
//   strk_total_stake: staker_total_strk_balance,
//   btc_total_stake:  staker_total_btc_balance,
// With:
let (strk_total_stake, btc_total_stake) =
    self.get_total_staking_power_at_epoch(epoch_id: curr_epoch);
```

The staker's own balance is still needed only for the non-zero assertion (line 1482) and can be kept for that purpose.

---

### Proof of Concept

1. Network has 100 stakers each with equal stake; total STRK stake = 1 000 000 tokens.
2. Staker A (1 000 tokens, 0.1 % share) monitors the mempool and submits `update_rewards(staker_A, false)` as the first transaction of each new block.
3. Inside `update_rewards`, `staker_total_strk_balance = 1 000` is passed as `strk_total_stake`.
4. `_update_rewards` computes staking power ∝ `1 000 / 1 000 = 1` (full weight).
5. Staker A is credited the entire `strk_block_rewards` for that block.
6. `last_reward_block` is updated; no other staker can claim rewards for that block.
7. Repeated every block, Staker A accumulates rewards 1 000× their fair share, constituting direct theft of unclaimed yield from all other stakers.

---

**Root cause lines:** [1](#0-0) 

**Correct reference (pre-consensus path):** [2](#0-1) 

**Denominator usage in staking-power helper:** [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L1406-1422)
```text
            let (strk_epoch_rewards, btc_epoch_rewards) = reward_supplier_dispatcher
                .calculate_current_epoch_rewards();
            let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let curr_epoch = self.get_current_epoch();
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_epoch_rewards,
                    btc_total_rewards: btc_epoch_rewards,
                    :strk_total_stake,
                    :btc_total_stake,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
```

**File:** src/staking/staking.cairo (L1474-1506)
```text
            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let (staker_total_strk_balance, staker_total_btc_balance) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, epoch_id: curr_epoch,
                );
            // Assert staker has non-zero balance.
            // Staker exists with zero balance for the first K epochs after `stake`, then the stake
            // becomes effective.
            assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);

            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }

            // Get current block data and update rewards.
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            let (strk_block_rewards, btc_block_rewards) = self
                .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_block_rewards,
                    btc_total_rewards: btc_block_rewards,
                    strk_total_stake: staker_total_strk_balance,
                    btc_total_stake: staker_total_btc_balance,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
```

**File:** src/staking/utils.cairo (L124-147)
```text
pub(crate) fn calculate_staker_total_staking_power(
    staker_strk_total_amount: NormalizedAmount,
    staker_btc_total_amount: NormalizedAmount,
    strk_total_stake: NormalizedAmount,
    btc_total_stake: NormalizedAmount,
) -> StakingPower {
    let strk_staking_power = mul_wide_and_div(
        lhs: staker_strk_total_amount.to_amount_18_decimals(),
        rhs: STRK_WEIGHT_FACTOR,
        div: strk_total_stake.to_amount_18_decimals(),
    )
        .unwrap();
    let btc_staking_power = if btc_total_stake.is_zero() {
        Zero::zero()
    } else {
        mul_wide_and_div(
            lhs: staker_btc_total_amount.to_amount_18_decimals(),
            rhs: BTC_WEIGHT_FACTOR,
            div: btc_total_stake.to_amount_18_decimals(),
        )
            .unwrap()
    };
    strk_staking_power + btc_staking_power
}
```
