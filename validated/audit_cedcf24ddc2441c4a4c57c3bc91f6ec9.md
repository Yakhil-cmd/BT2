### Title
Missing Caller Restriction on `update_rewards` Allows Any Account to Freeze Staker Yield - (File: `src/staking/staking.cairo`)

### Summary

The `update_rewards` function in the Staking contract is documented to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can invoke it, consuming the single per-block reward slot and preventing the sequencer from distributing rewards to stakers for that block.

### Finding Description

The protocol specification explicitly states:

> **access control**: Only starkware sequencer.

for `update_rewards`. [1](#0-0) 

However, the implementation in `StakingRewardsManagerImpl` performs no such check: [2](#0-1) 

The function only validates:
1. Contract is not paused (`general_prerequisites`)
2. `current_block_number > self.last_reward_block.read()` — enforcing at most one call per block

After a successful call, `last_reward_block` is written to the current block number, making any subsequent call in the same block revert with `REWARDS_ALREADY_UPDATED`. Because `last_reward_block` is a **global** (non-per-staker) storage variable, a single call by any address exhausts the entire block's reward slot for all stakers. [3](#0-2) [4](#0-3) 

The analog to the external report is direct: just as `BeamInitializable.initialize` was public and callable by any account (allowing an attacker to hijack the bootstrap process), `update_rewards` is public and callable by any account, allowing an attacker to hijack the per-block reward distribution slot.

### Impact Explanation

An attacker calls `update_rewards(victim_staker, disable_rewards: true)` at every block before the sequencer does. Each such call:
- Sets `last_reward_block` to the current block
- Distributes **zero** rewards (because `disable_rewards = true` causes an early return)
- Blocks the sequencer's legitimate call for that block with `REWARDS_ALREADY_UPDATED`

If sustained, all stakers permanently miss their consensus-era block rewards. This constitutes **permanent freezing of unclaimed yield** (High impact).

Even a single-block attack causes stakers to lose one block's worth of rewards with no recourse, since `last_reward_block` cannot be reset by governance.

### Likelihood Explanation

In Starknet, the sequencer controls transaction ordering within a block and can place its own `update_rewards` call first. This limits exploitability under normal sequencer operation. However:

- The sequencer may not call `update_rewards` in every block (e.g., during low-activity periods or sequencer downtime), leaving the slot open for an attacker.
- There is no on-chain enforcement preventing a racing transaction from being included first.
- The attack requires no capital, no special role, and no prior setup — any address can execute it.

Likelihood is **Medium** under normal sequencer operation, escalating to **High** during any sequencer disruption.

### Recommendation

Add an explicit caller check matching the specification. Store the authorized sequencer address at construction time and assert it in `update_rewards`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of function
}
```

Alternatively, if the sequencer address is not known at deploy time, use the existing roles system (e.g., an `OPERATOR` role) to gate this function, consistent with how other privileged functions are protected. [5](#0-4) 

### Proof of Concept

```cairo
// Any unprivileged address can call this after K epochs when consensus rewards are active:
let staking_rewards = IStakingRewardsManagerDispatcher {
    contract_address: staking_contract,
};

// Attacker calls at block N with disable_rewards=true:
// - last_reward_block is set to N
// - zero rewards distributed
staking_rewards.update_rewards(
    staker_address: any_staker,
    disable_rewards: true,
);

// Sequencer's legitimate call at block N now reverts:
// REWARDS_ALREADY_UPDATED
staking_rewards.update_rewards(
    staker_address: victim_staker,
    disable_rewards: false,
); // panics
```

Repeat every block → all stakers permanently receive zero consensus rewards.

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1392-1400)
```text
    #[abi(embed_v0)]
    impl StakingAttestationImpl of IStakingAttestation<ContractState> {
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
```

**File:** src/staking/staking.cairo (L1449-1507)
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
```
