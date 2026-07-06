### Title
Unrestricted `update_rewards` with `disable_rewards: true` Allows Any Caller to Permanently Freeze All Staker Consensus Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract has no access control and accepts a caller-controlled `disable_rewards` flag. A global `last_reward_block` lock is written **before** the `disable_rewards` guard, so any unprivileged address can call `update_rewards(any_active_staker, disable_rewards: true)` once per block to consume the block's single reward slot without distributing any rewards. Repeating this every block permanently prevents all stakers from receiving consensus (V3) block rewards.

---

### Finding Description

`update_rewards` is the sole mechanism for distributing consensus-mode (V3) block rewards to stakers. Its access control is limited to `general_prerequisites()`, which only checks that the contract is unpaused and the caller is non-zero — no role restriction exists. [1](#0-0) 

The function writes `last_reward_block` to the current block number **before** checking `disable_rewards`: [2](#0-1) 

Because `last_reward_block` is a single global storage variable (not per-staker), once it is written in block N, the assertion `current_block_number > last_reward_block` fails for every subsequent call in the same block: [3](#0-2) 

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` in block N:
1. Passes all precondition checks (staker exists, has non-zero balance at current epoch).
2. Writes `last_reward_block = N`.
3. Returns early — no rewards are calculated or distributed.
4. Blocks every other call to `update_rewards` for the remainder of block N.

The `update_rewards_from_attestation_contract` (V2 path) correctly restricts callers: [4](#0-3) 

No equivalent guard exists on the V3 path.

The balance-at-epoch lookup used to validate the staker is sound (uses `<=`), so the attacker only needs any currently-active staker address with non-zero balance — trivially obtainable from on-chain state: [5](#0-4) 

---

### Impact Explanation

In V3 consensus mode, `update_rewards` is the only path through which block rewards reach stakers and their delegation pools. Each block for which the attacker fires the griefing call results in **permanently lost block rewards** — the reward supplier's `unclaimed_rewards` is never incremented, and the tokens are never transferred. Stakers and pool members accumulate zero yield for every griefed block. This constitutes **permanent freezing of unclaimed yield** for the entire protocol while the attack is sustained.

---

### Likelihood Explanation

- No privileged role, no special token, no flash-loan required.
- The attacker only needs a valid active staker address (public on-chain) and enough gas to submit one transaction per block.
- On Starknet, gas costs are low; the attack is economically viable indefinitely.
- The attacker gains nothing directly, but a competitor, short-seller, or protocol adversary has clear motive.

---

### Recommendation

Restrict `update_rewards` to an authorized caller (e.g., the consensus layer contract address stored in contract storage), mirroring the pattern already used for `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.general_prerequisites();
    self.assert_caller_is_consensus_contract(); // add this guard
    ...
}
```

Alternatively, move the `last_reward_block` write to **after** the `disable_rewards` guard so that a `disable_rewards: true` call does not consume the block's reward slot.

---

### Proof of Concept

```
// Pseudocode — executable with Starknet Foundry
fn test_grief_consensus_rewards() {
    // Setup: staker stakes, K epochs pass, consensus rewards active.
    let staker = deploy_and_stake();
    advance_k_epochs();
    set_consensus_rewards_first_epoch(current_epoch());

    let attacker = address(0xdead);
    let staking = IStakingRewardsManagerDispatcher { contract_address: staking_contract };

    // In every block, attacker calls update_rewards with disable_rewards=true.
    loop {
        advance_block();
        cheat_caller_address_once(staking_contract, attacker);
        // Uses any active staker address; disable_rewards=true wastes the slot.
        staking.update_rewards(staker_address, disable_rewards: true);
        // Legitimate consensus-layer call now fails: REWARDS_ALREADY_UPDATED.
        let result = staking_safe.update_rewards(staker_address, disable_rewards: false);
        assert!(result.is_err()); // REWARDS_ALREADY_UPDATED
    }

    // After N blocks, staker has received zero rewards.
    let info = staking.staker_info_v1(staker_address);
    assert!(info.unclaimed_rewards_own == 0);
}
```

### Citations

**File:** src/staking/staking.cairo (L1399-1401)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

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

**File:** src/staking/utils.cairo (L95-110)
```text
pub(crate) fn balance_at_epoch(trace: StoragePath<Trace>, epoch_id: Epoch) -> NormalizedAmount {
    let (epoch, balance) = trace.last().unwrap_or_else(|err| panic!("{err}"));
    let current_balance = if epoch <= epoch_id {
        balance
    } else {
        let (epoch, balance) = trace.second_last().unwrap_or_else(|err| panic!("{err}"));
        if epoch <= epoch_id {
            balance
        } else {
            let (epoch, balance) = trace.third_last().unwrap_or_else(|err| panic!("{err}"));
            assert!(epoch <= epoch_id, "{}", InternalError::INVALID_THIRD_LAST);
            balance
        }
    };
    NormalizedAmountTrait::from_amount_18_decimals(amount: current_balance)
}
```
