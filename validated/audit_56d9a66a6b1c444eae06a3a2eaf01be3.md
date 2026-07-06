### Title
Unprivileged Caller Can Corrupt `last_reward_block` via `update_rewards(disable_rewards=true)`, Permanently Blocking Consensus Reward Distribution - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract has no access control and accepts a caller-controlled `disable_rewards` flag. Because `last_reward_block` is written to storage **before** the `disable_rewards` check, any unprivileged caller can front-run the legitimate reward-distribution call, mark the block as already processed, and cause all stakers to permanently lose their consensus rewards for that block. The attack is repeatable every block.

---

### Finding Description

`StakingRewardsManagerImpl::update_rewards` is a public function gated only by `general_prerequisites` (contract not paused, caller not zero address). No role check or caller whitelist exists. [1](#0-0) 

The function body executes in this order:

1. Asserts `current_block_number > last_reward_block` — the one-per-block guard.
2. Validates that `staker_address` is active with non-zero balance.
3. **Unconditionally writes `last_reward_block = current_block_number`.**
4. Checks `if disable_rewards || self.is_pre_consensus() { return; }` — skips reward distribution. [2](#0-1) 

Step 3 commits the block as "processed" regardless of whether rewards were actually distributed. An attacker who calls `update_rewards(any_valid_active_staker, disable_rewards: true)` at block N will:

- Set `last_reward_block = N` (step 3).
- Return immediately without distributing any rewards (step 4).

Any subsequent legitimate call to `update_rewards` for block N will fail at step 1 with `REWARDS_ALREADY_UPDATED`, because `current_block_number > last_reward_block` is now false. [3](#0-2) 

`last_reward_block` is a global, monotonically-advancing guard — there is no mechanism to "undo" a processed block. The rewards for block N are permanently lost.

The only input the attacker must supply is a valid, active staker address with non-zero STRK balance at the current epoch, which is fully observable on-chain via `get_stakers` or emitted events. [4](#0-3) 

---

### Impact Explanation

Each block, `update_rewards` is the sole mechanism for distributing consensus (V3) block rewards to stakers and their delegation pools. Skipping it for a block permanently destroys those rewards — they are never re-queued or carried forward. An attacker who repeats this call at the start of every block causes **permanent freezing of all unclaimed consensus yield** for every staker in the protocol.

This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

**High.** The attack requires:
- No privileged role or leaked key.
- No capital at risk.
- Only a valid active staker address (publicly observable on-chain).

The attacker can call `update_rewards(valid_staker, true)` at the beginning of every block, or simply monitor the mempool and front-run the legitimate caller. On Starknet, transaction ordering within a block is deterministic and front-running is feasible. The cost is only gas.

---

### Recommendation

1. **Add access control**: Restrict `update_rewards` to the attestation contract (or another authorized caller), consistent with how `update_rewards_from_attestation_contract` is protected. [5](#0-4) 

2. **Move the write after the guard**: If open access is intentional, move `self.last_reward_block.write(current_block_number)` to after the `disable_rewards` check, so that a skipped block is not marked as processed.

3. **Remove or restrict `disable_rewards`**: If the parameter is only meaningful for the attestation contract, remove it from the public interface or enforce that only the attestation contract may pass `true`.

---

### Proof of Concept

```
Block N arrives.

1. Attacker observes any active staker address S with non-zero STRK balance.
2. Attacker calls: staking.update_rewards(staker_address=S, disable_rewards=true)
   - last_reward_block is written to N.
   - Function returns early; no rewards distributed.
3. Legitimate caller (e.g., attestation contract) calls:
   staking.update_rewards(staker_address=S, disable_rewards=false)
   - Assert: current_block_number (N) > last_reward_block (N) → FAILS with REWARDS_ALREADY_UPDATED.
4. All stakers lose their block-N consensus rewards permanently.
5. Attacker repeats at block N+1, N+2, … → all consensus rewards are frozen indefinitely.
```

### Citations

**File:** src/staking/staking.cairo (L1393-1401)
```text
    impl StakingAttestationImpl of IStakingAttestation<ContractState> {
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1448-1452)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
```

**File:** src/staking/staking.cairo (L1453-1458)
```text
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1460-1482)
```text
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
