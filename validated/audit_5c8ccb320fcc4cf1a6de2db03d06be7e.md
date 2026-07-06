### Title
Unprivileged Caller Can Permanently Freeze Consensus Rewards for All Stakers via `update_rewards(disable_rewards: true)` Front-Running — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract accepts an unguarded `disable_rewards: bool` parameter. Because `last_reward_block` is a **single global** storage variable, any unprivileged caller can front-run every legitimate `update_rewards` call with `disable_rewards: true`, consuming the per-block reward slot without distributing any rewards. Repeated across every block, this permanently freezes unclaimed consensus-epoch yield for all stakers.

---

### Finding Description

`update_rewards` is a public function gated only by `general_prerequisites` (contract not paused, caller not zero address). It contains two critical properties that interact badly:

**1. Global `last_reward_block` gate** [1](#0-0) 

```cairo
let current_block_number = starknet::get_block_number();
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

Only one call to `update_rewards` can succeed per block, for **any** staker. Once `last_reward_block` is written, every subsequent call in the same block reverts.

**2. `disable_rewards` writes `last_reward_block` without distributing rewards** [2](#0-1) 

```cairo
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
```

When `disable_rewards: true`, the function:
- Writes `last_reward_block = current_block_number` (consuming the slot)
- Returns immediately — no rewards are calculated or distributed

**3. No access control on `disable_rewards`** [3](#0-2) 

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
```

`general_prerequisites` only asserts the contract is unpaused and the caller is non-zero. Any EOA can pass `disable_rewards: true`.

**4. `last_reward_block` is a single global variable** [4](#0-3) 

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
```

One attacker call blocks **all** stakers from receiving rewards in that block, not just the targeted staker.

---

### Impact Explanation

In V3 consensus-rewards mode (`is_pre_consensus() == false`), block rewards are the sole mechanism for distributing yield to stakers. An attacker who calls `update_rewards(any_staker, disable_rewards: true)` in every block:

- Consumes the single per-block reward slot
- Distributes zero rewards
- Forces every legitimate `update_rewards` call to revert with `REWARDS_ALREADY_UPDATED`

The rewards are not redistributed — they remain unclaimed in the `RewardSupplier`. Stakers' `unclaimed_rewards_own` fields are never incremented. This constitutes **permanent freezing of unclaimed yield** for all stakers as long as the attacker sustains the attack.

Impact classification: **High — Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

Starknet transaction fees are low. Calling one transaction per block is inexpensive. The attacker needs no privileged role, no special token balance, and no coordination. The attack is permissionless and can be automated with a simple bot. The only cost is gas per block.

Likelihood: **Medium** (requires sustained effort but is economically trivial on Starknet L2).

---

### Recommendation

1. **Remove `disable_rewards` from the public interface** or restrict it to a privileged role (e.g., `only_security_agent`).
2. **Make `last_reward_block` per-staker** rather than global, so one call cannot block all others.
3. Alternatively, only update `last_reward_block` when rewards are actually distributed (i.e., move the write inside the `if !disable_rewards` branch).

---

### Proof of Concept

```
Epoch E, Block N (V3 consensus rewards active):

1. Attacker calls: update_rewards(staker_A, disable_rewards=true)
   → last_reward_block = N
   → No rewards distributed
   → Returns early

2. Staker B calls: update_rewards(staker_B, disable_rewards=false)
   → assert!(N > N) → FAILS with REWARDS_ALREADY_UPDATED

3. Staker C calls: update_rewards(staker_C, disable_rewards=false)
   → assert!(N > N) → FAILS

Block N+1:
4. Attacker calls: update_rewards(staker_A, disable_rewards=true)
   → last_reward_block = N+1
   → No rewards distributed

... repeated every block ...

Result: staker_B.unclaimed_rewards_own and staker_C.unclaimed_rewards_own
        are never incremented. All consensus yield is permanently frozen.
``` [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1507)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );

            // Assert staker exists and active.
            // Staker is considered to exist from the moment of `stake` (when `InternalStakerInfo`
            // struct is created) until the calling to `unstake_action` (when `InternalStakerInfo`
            // struct is deleted).
            // Staker remains active until the intent period begins, i.e. K epochs after
            // `unstake_intent` is called.
            let staker_info = self.internal_staker_info(:staker_address);
            let curr_epoch = self.get_current_epoch();
            assert!(
                self.is_staker_active(:staker_address, epoch_id: curr_epoch),
                "{}",
                Error::INVALID_STAKER,
            );

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
        }
```
