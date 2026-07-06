### Title
Front-running `update_rewards` via global `last_reward_block` enables permanent freezing of consensus rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `src/staking/staking.cairo` enforces a single-call-per-block constraint using a **global** `last_reward_block` storage variable. Because the function is unpermissioned and accepts a caller-controlled `disable_rewards: bool` flag, any unprivileged actor can front-run every legitimate `update_rewards` call by submitting `update_rewards(any_valid_staker, disable_rewards: true)` first in each block. This consumes the block's reward slot while distributing zero rewards, permanently freezing consensus-phase unclaimed yield for targeted stakers.

---

### Finding Description

**Root cause — global `last_reward_block` + no access control + caller-controlled `disable_rewards`**

`update_rewards` is the sole mechanism for distributing per-block consensus rewards to stakers (post `consensus_rewards_first_epoch`). [1](#0-0) 

The function opens with a block-number gate:

```cairo
let current_block_number = starknet::get_block_number();
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [2](#0-1) 

`last_reward_block` is a **single global slot** — not per-staker: [3](#0-2) 

After passing the gate, the function unconditionally writes the current block number:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);
``` [4](#0-3) 

Then it checks `disable_rewards`:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [5](#0-4) 

There is **no role check** anywhere in the function — `general_prerequisites()` only verifies the contract is not paused. Any address may call `update_rewards(staker_address, disable_rewards: true)` for any valid staker.

The combination means:

1. Attacker calls `update_rewards(victim_staker, true)` at the start of block N.
2. `last_reward_block` is set to N; the function returns without distributing rewards.
3. Every subsequent `update_rewards` call in block N reverts with `REWARDS_ALREADY_UPDATED`.
4. Repeated across every block, the victim's consensus rewards are permanently frozen.

---

### Impact Explanation

In the consensus phase, `update_rewards` is the **only** path through which per-block STRK/BTC rewards accrue to a staker's `unclaimed_rewards_own`. The pre-consensus path (`update_rewards_from_attestation_contract`) is gated to the attestation contract and is disabled once consensus rewards are active: [6](#0-5) 

If an attacker continuously occupies the global `last_reward_block` slot with `disable_rewards: true`, the targeted staker's `unclaimed_rewards_own` never increases. This constitutes **permanent freezing of unclaimed yield** — a High-severity impact under the allowed scope.

---

### Likelihood Explanation

- The function is fully public; no privileged key or role is required.
- The attacker only needs to submit one transaction per block, which is inexpensive on Starknet.
- The attack requires no profit motive; it is pure griefing.
- The attacker can target a single staker (by always passing that staker's address) or all stakers simultaneously (by cycling through valid staker addresses).
- There is no on-chain defense: the victim cannot "outbid" the attacker because Starknet's sequencer ordering is not a public mempool auction in the same way as Ethereum, but transaction ordering within a block is still exploitable by a determined actor (e.g., the attacker themselves operating a node or colluding with the sequencer).

---

### Recommendation

1. **Add access control**: Restrict `update_rewards` (especially the `disable_rewards: true` path) to a trusted role (e.g., `APP_GOVERNOR` or a dedicated consensus-rewards caller address).
2. **Per-staker last-reward tracking**: Replace the single global `last_reward_block` with a `Map<ContractAddress, BlockNumber>` so that one staker's reward update does not block all others.
3. **Separate the disable path**: If `disable_rewards: true` is intended for the consensus mechanism to penalize non-participating stakers, gate it behind a role check so unprivileged callers cannot invoke it.

---

### Proof of Concept

```
// Attacker script (pseudocode, one call per block):
loop every block N:
    staking_contract.update_rewards(
        staker_address = victim,   // any valid staker
        disable_rewards = true
    )
    // Effect:
    //   last_reward_block := N
    //   victim receives 0 rewards
    //   all other update_rewards calls in block N revert with REWARDS_ALREADY_UPDATED
```

Concrete call path:

1. `update_rewards(victim, true)` — passes `general_prerequisites()` (contract not paused).
2. `current_block_number > last_reward_block` — passes (first call in block).
3. Staker existence and active checks pass (victim is a valid staker).
4. `last_reward_block.write(current_block_number)` — slot consumed.
5. `if disable_rewards { return; }` — exits without updating `unclaimed_rewards_own`.
6. Any legitimate `update_rewards(victim, false)` in the same block hits the assert at step 2 and reverts. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1394-1400)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
```

**File:** src/staking/staking.cairo (L1449-1510)
```text
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
    }

    #[generate_trait]
```
