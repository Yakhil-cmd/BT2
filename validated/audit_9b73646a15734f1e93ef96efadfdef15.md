### Title
Unprivileged caller can invoke `update_rewards` with `disable_rewards=true` to permanently freeze all staker yield — (File: `src/staking/staking.cairo`)

---

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` is a public, access-control-free entry point that accepts a caller-controlled `disable_rewards: bool` parameter. When set to `true`, the function advances the global `last_reward_block` to the current block without distributing any rewards. Because only one call per block is permitted, an attacker who calls this first in every block permanently prevents the legitimate consensus mechanism from distributing rewards to any staker.

---

### Finding Description

`update_rewards` is declared as `#[abi(embed_v0)]` with no role check beyond `general_prerequisites()`, which only verifies the contract is unpaused and the caller is non-zero:

```cairo
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();                          // only: unpaused + caller != 0
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        ...
        // Update last block rewards.
        self.last_reward_block.write(current_block_number);   // <-- global slot consumed

        if disable_rewards || self.is_pre_consensus() {
            return;                                           // <-- no rewards distributed
        }
        ...
    }
}
``` [1](#0-0) 

`last_reward_block` is a single global storage slot shared across all stakers:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [2](#0-1) 

The guard `current_block_number > last_reward_block` means only **one** call per block is accepted. An attacker who calls `update_rewards(valid_staker, disable_rewards: true)` first in a block:

1. Passes all validation (staker exists, is active, has non-zero balance).
2. Writes `last_reward_block = current_block_number`.
3. Returns early — zero rewards distributed.

Any subsequent call by the legitimate consensus mechanism in the same block reverts with `REWARDS_ALREADY_UPDATED`. Repeating this every block permanently prevents all consensus reward distribution.

The `general_prerequisites` function confirms there is no access control:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [3](#0-2) 

---

### Impact Explanation

An attacker calling `update_rewards(valid_staker, true)` at the start of every block permanently freezes all staker consensus rewards. No staker — own or delegated — receives any yield from the consensus reward phase. This constitutes **permanent freezing of unclaimed yield** for the entire protocol.

The analog to the external report is exact: in the report, an uncapped user-supplied `probability` corrupts a shared aggregate (`probabilityAverage`); here, an unchecked user-supplied `disable_rewards=true` corrupts the shared global slot `last_reward_block`, blocking all reward accounting for that block.

---

### Likelihood Explanation

- The function is publicly callable with no privilege requirement.
- Valid staker addresses are observable on-chain via emitted events (`NewStaker`).
- The only cost to the attacker is gas per block; on Starknet this is low.
- No special knowledge or setup is required beyond knowing a live staker address.

---

### Recommendation

Restrict `update_rewards` to authorized callers only (e.g., the consensus layer or a designated operator role), mirroring how `update_rewards_from_attestation_contract` is restricted to the attestation contract:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   self.assert_caller_is_consensus_contract(); // add access control
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface and expose reward disabling only through a privileged, role-gated function. [4](#0-3) 

---

### Proof of Concept

```
1. Attacker observes any active staker address (e.g., from a NewStaker event).
2. At the start of each block, attacker calls:
       staking.update_rewards(valid_staker_address, disable_rewards: true)
3. The function passes all checks (staker active, non-zero balance).
4. last_reward_block is written to the current block number.
5. The legitimate consensus mechanism's call to update_rewards in the same block
   reverts with REWARDS_ALREADY_UPDATED.
6. No staker receives block rewards for that block.
7. Repeated every block → all consensus-phase staker yield is permanently frozen.
```

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1490)
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

```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L2219-2225)
```text
        fn assert_caller_is_attestation_contract(self: @ContractState) {
            assert!(
                get_caller_address() == self.attestation_contract.read(),
                "{}",
                Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
            );
        }
```
