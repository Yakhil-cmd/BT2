### Title
Unprivileged Caller Can Freeze Consensus Reward Distribution by Front-Running `update_rewards` with `disable_rewards: true` — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract is callable by any non-zero address and accepts a `disable_rewards` boolean parameter. When called with `disable_rewards: true`, it writes the current block number into the global `last_reward_block` storage slot without distributing any rewards. Because a subsequent call in the same block unconditionally reverts with `REWARDS_ALREADY_UPDATED`, an attacker can permanently suppress consensus reward distribution by submitting this call every block, front-running the legitimate sequencer/consensus invocation.

---

### Finding Description

`update_rewards` is exposed as a public ABI entry point under `IStakingRewardsManager`. Its only gate is `general_prerequisites`, which checks that the contract is not paused and the caller is non-zero — no role or authorization check exists. [1](#0-0) 

After validating that the supplied `staker_address` is active and has a non-zero STRK balance, the function unconditionally writes `current_block_number` into `last_reward_block`: [2](#0-1) 

When `disable_rewards` is `true`, execution returns immediately after that write — no rewards are computed or transferred. The write itself is the damage: any subsequent call to `update_rewards` in the same block hits the guard at line 1454–1458 and reverts with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

Because `last_reward_block` is a **single global slot** (not per-staker), one attacker transaction per block is sufficient to consume the entire block's reward slot for all stakers.

The `disable_rewards` path is only meaningful in consensus mode (after `consensus_rewards_first_epoch`). In that mode, the consensus mechanism is expected to call `update_rewards` once per block for the designated staker. An attacker who submits `update_rewards(any_active_staker, disable_rewards: true)` before that call occupies the slot, the legitimate call reverts, and no staker receives block rewards for that block. [4](#0-3) 

---

### Impact Explanation

Every block in which the attacker front-runs the consensus call, **all stakers lose their block rewards permanently** — there is no catch-up mechanism; missed blocks are not retroactively compensated. Sustained over many blocks this constitutes a **permanent freezing of unclaimed yield** for the entire staker set. Even intermittent execution constitutes **temporary freezing of unclaimed yield**, which is within the allowed impact scope.

---

### Likelihood Explanation

- `update_rewards` is a public, permissionless entry point — no special role or stake is required.
- The attacker only needs a valid, active staker address (trivially obtained from on-chain events or `get_stakers`).
- On Starknet the sequencer orders transactions; an attacker who submits with a competitive fee can reliably precede the consensus call each block.
- The per-block gas cost is low relative to the aggregate yield stolen from all stakers.
- No profit motive is required; pure griefing suffices.

---

### Recommendation

Restrict `update_rewards` (and specifically the `disable_rewards: true` path) to an authorized caller — either the consensus contract address stored in a dedicated storage slot, or a dedicated role (e.g., `OPERATOR_ROLE`). The simplest fix is to add an `assert!(get_caller_address() == self.consensus_contract.read(), ...)` guard at the top of `update_rewards`, mirroring the pattern already used in `update_rewards_from_attestation_contract`: [5](#0-4) 

Alternatively, split the function into two: a public `tick_reward_block` (no rewards, no `disable_rewards` flag) and a privileged `distribute_block_rewards` callable only by the consensus layer.

---

### Proof of Concept

1. Consensus mode is active (`get_current_epoch() >= consensus_rewards_first_epoch`).
2. Each block, the consensus layer is expected to call `update_rewards(staker_X, false)` to distribute block rewards.
3. Attacker submits `update_rewards(staker_X, true)` with a higher fee in the same block.
4. Sequencer includes the attacker's transaction first; `last_reward_block` is set to block `N`; no rewards are distributed.
5. The consensus call arrives and reverts: `current_block_number (N) > last_reward_block (N)` is false → `REWARDS_ALREADY_UPDATED`.
6. Block `N` yields zero rewards for every staker.
7. Attacker repeats in block `N+1`, `N+2`, … indefinitely.

The attacker pays only gas; stakers lose all consensus-phase block rewards for the duration of the attack.

### Citations

**File:** src/staking/staking.cairo (L1398-1401)
```text
            self.general_prerequisites();
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
