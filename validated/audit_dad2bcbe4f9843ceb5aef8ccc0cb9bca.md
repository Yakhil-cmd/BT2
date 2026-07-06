### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Freeze Yield Distribution — (`src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is callable by any address despite the specification requiring "Only starkware sequencer." Because the global `last_reward_block` is updated unconditionally on every successful call, an attacker can call `update_rewards(valid_staker, disable_rewards: true)` at the start of every block to consume the per-block reward slot without distributing any rewards, permanently blocking all stakers and delegators from accruing yield.

---

### Finding Description

The `update_rewards` function in `src/staking/staking.cairo` performs no caller authentication: [1](#0-0) 

The only guard is `general_prerequisites()` (which only checks the pause flag) and the `REWARDS_ALREADY_UPDATED` assertion. After passing those checks, the function unconditionally writes the current block number to the **global** `last_reward_block` storage slot: [2](#0-1) 

Because `last_reward_block` is a single global value (not per-staker), one successful call per block exhausts the reward slot for **all** stakers in that block. When `disable_rewards: true` is passed, the function returns immediately after updating `last_reward_block`, distributing nothing: [3](#0-2) 

The specification explicitly restricts this function to the Starknet sequencer: [4](#0-3) 

No such check exists in the implementation.

---

### Impact Explanation

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` once per block:

1. Sets `last_reward_block` to the current block number.
2. Causes every subsequent call to `update_rewards` in that block (including the legitimate sequencer's call) to revert with `REWARDS_ALREADY_UPDATED`.
3. Prevents all stakers and their delegation pools from accruing any block rewards for that block.

Repeated every block, this permanently freezes unclaimed yield for the entire protocol. This matches the **High** allowed impact: *"Permanent freezing of unclaimed yield or unclaimed royalties."*

---

### Likelihood Explanation

- No special role or privilege is required; any externally-owned address can call `update_rewards`.
- The attacker only needs to supply a valid, active `staker_address` (publicly readable from on-chain state) to pass the `STAKER_NOT_EXISTS` / `INVALID_STAKER` assertions.
- The cost is one transaction per block; on Starknet this is low enough to sustain indefinitely.
- There is no on-chain mechanism to evict or penalize the attacker.

---

### Recommendation

Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the registered sequencer address (or a governance-controlled allowlist), mirroring the pattern used in `update_unclaimed_rewards_from_staking_contract`: [5](#0-4) 

---

### Proof of Concept

```
1. Deploy / use the existing staking system with at least one active staker (staker_A).
2. At the start of block N, attacker calls:
       staking.update_rewards(staker_A, disable_rewards: true)
   → last_reward_block is set to N; no rewards distributed.
3. Sequencer attempts:
       staking.update_rewards(staker_A, disable_rewards: false)
   → reverts: "Rewards were already updated for the current block"
4. Repeat step 2 at block N+1, N+2, … indefinitely.
5. All stakers' `unclaimed_rewards_own` and all pool reward traces remain frozen.
   Delegators calling `claim_rewards` receive 0 for every affected block.
```

### Citations

**File:** src/staking/staking.cairo (L1449-1458)
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/reward_supplier/reward_supplier.cairo (L192-196)
```text
            assert!(
                get_caller_address() == self.staking_contract.read(),
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
```
