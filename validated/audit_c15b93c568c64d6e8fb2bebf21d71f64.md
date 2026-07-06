Based on my investigation of the `update_rewards` implementation and the spec, here is my analysis:

**Key findings:**

1. The spec explicitly states access control is **"Only starkware sequencer"** for `update_rewards`. [1](#0-0) 

2. The actual implementation has **no caller check** — only `general_prerequisites()` (pause check) is called before proceeding. [2](#0-1) 

3. The `last_reward_block` gate is **global** (not per-staker). Once any call succeeds for block N, no further reward distribution is possible for block N for any staker. [3](#0-2) 

4. The caller freely chooses both `staker_address` and `disable_rewards`. [4](#0-3) 

---

### Title
Missing Caller Access Control on `update_rewards` Allows Any Address to Suppress or Redirect Block Rewards — (`src/staking/staking.cairo`)

### Summary
`update_rewards` is specified as callable only by the Starknet sequencer, but the implementation enforces no such check. Any unprivileged address can call it, choose any `staker_address`, and set `disable_rewards: true`, permanently consuming the global per-block reward slot without distributing rewards to anyone.

### Finding Description
The `IStakingRewardsManager::update_rewards` function is gated only by a global `last_reward_block` check: if `current_block_number > last_reward_block`, the call proceeds and immediately writes `last_reward_block = current_block_number`. There is no `get_caller_address()` check, no role assertion, and no sequencer-address validation anywhere in the function body or in `general_prerequisites()`. [5](#0-4) 

Because `last_reward_block` is a single contract-wide storage slot, the first call in any block wins. An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` before the sequencer's intended call:
- Writes `last_reward_block` to the current block.
- Returns early without distributing any rewards (line 1487–1488).
- Makes every subsequent call in the same block revert with `REWARDS_ALREADY_UPDATED`.

The intended validator receives zero rewards for that block, and those rewards are permanently lost — there is no catch-up or retroactive mechanism.

Alternatively, the attacker can call `update_rewards(attacker_staker, disable_rewards: false)` to redirect the entire block's reward to their own staker instead of the sequencer-intended validator.

### Impact Explanation
Each suppressed block permanently discards the STRK (and BTC) block rewards that would have accrued to the targeted staker's `unclaimed_rewards_own`. There is no replay or compensation path. Sustained over many blocks, this constitutes **permanent freezing of unclaimed yield** for targeted validators.

### Likelihood Explanation
The function is public with no access control. Any EOA or contract can call it. On Starknet, user transactions are sequenced by the sequencer, but the sequencer processes user-submitted transactions alongside its own. If the sequencer's `update_rewards` call is not the first transaction in a block (or if the sequencer omits it), an attacker's transaction can win the slot. The attacker needs only to submit a valid transaction referencing any active staker.

### Recommendation
Add a caller check enforcing that only the designated Starknet sequencer address (or a whitelisted operator role) can invoke `update_rewards`, consistent with the spec's stated access control:

```cairo
let caller = get_caller_address();
assert!(caller == self.sequencer_address.read(), "{}", Error::ONLY_SEQUENCER);
```

### Proof of Concept
1. Deploy two active stakers, `staker_A` (intended recipient) and `staker_B` (attacker-controlled).
2. In block N, before the sequencer's call, submit: `update_rewards(staker_B, disable_rewards: true)`.
3. `last_reward_block` is set to N; no rewards are distributed.
4. Sequencer's call for `staker_A` reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat for every block in an epoch — `staker_A` accumulates zero rewards despite being active and eligible.
6. Compare `staker_A.unclaimed_rewards_own` against the expected model: it remains zero while it should have grown by `block_rewards × (staker_A_stake / total_stake)` per block.

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1449-1489)
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
