### Title
Unrestricted `update_rewards` with `disable_rewards=true` Allows Anyone to Permanently Freeze Consensus Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract is publicly callable by any address and accepts a caller-controlled `disable_rewards` boolean. Because `last_reward_block` is a single global storage variable that gates the function to one execution per block, an attacker can call `update_rewards(any_valid_staker, disable_rewards: true)` on every block to consume the single allowed update slot without distributing rewards, permanently freezing consensus-phase yield for all stakers.

### Finding Description
`update_rewards` is exposed via `#[abi(embed_v0)]` in `StakingRewardsManagerImpl` with no caller restriction:

```cairo
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
    ...
    self.last_reward_block.write(current_block_number);   // ← global slot consumed

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← no rewards distributed
    }
    ...
``` [1](#0-0) 

The storage field `last_reward_block` is a single protocol-wide counter:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [2](#0-1) 

Because the assert at line 1454 enforces `current_block_number > last_reward_block`, only **one** successful call to `update_rewards` is possible per block across the entire protocol. When `disable_rewards` is `true`, the function writes `last_reward_block` and returns immediately without distributing any rewards. There is no check that the caller is the staker, the staker's reward address, or any privileged role.

By contrast, the analogous pre-consensus path (`update_rewards_from_attestation_contract`) correctly enforces `self.assert_caller_is_attestation_contract()`:

```cairo
fn update_rewards_from_attestation_contract(
    ref self: ContractState, staker_address: ContractAddress,
) {
    self.general_prerequisites();
    assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
    self.assert_caller_is_attestation_contract();   // ← access control present
``` [3](#0-2) 

`update_rewards` has no equivalent guard.

### Impact Explanation
In the consensus-rewards phase, every block that a staker's `update_rewards` call is displaced by an attacker's `disable_rewards: true` call is a block for which **no staker in the protocol receives block rewards**. An attacker who repeats this on every block permanently freezes all consensus-phase unclaimed yield. This maps directly to the allowed High impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation
- The attacker needs only a valid, active staker address — all staker addresses are publicly observable from `NewStaker` events.
- The call itself is cheap (a single Starknet transaction per block).
- No privileged access, leaked key, or external dependency is required.
- The attacker has no profit motive but can inflict severe, sustained damage on all stakers and delegators.

### Recommendation
Add a caller restriction to `update_rewards`. The simplest fix is to require the caller to be the staker address or the staker's reward address (mirroring the pattern used in `claim_rewards`). Alternatively, if `disable_rewards` is only needed for internal protocol transitions, move that logic into an internal helper and remove the parameter from the public ABI.

### Proof of Concept
1. Consensus rewards are activated (`consensus_rewards_first_epoch` is set and reached).
2. Attacker observes any active staker address `S` from on-chain events.
3. On every new block, attacker submits the first transaction:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. The function passes all checks (staker exists, block is new), writes `last_reward_block = current_block`, and returns without distributing rewards.
5. Any subsequent legitimate call to `update_rewards` in the same block fails with `REWARDS_ALREADY_UPDATED`.
6. Repeated every block, no staker ever accumulates consensus rewards; all unclaimed yield is permanently frozen. [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1449-1490)
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

```
