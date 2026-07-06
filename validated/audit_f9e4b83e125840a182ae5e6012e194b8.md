### Title
Missing Caller Validation in `update_rewards` Allows Any Address to Permanently Deny Block Rewards — (File: `src/staking/staking.cairo`)

### Summary

`IStakingRewardsManager::update_rewards` in `src/staking/staking.cairo` contains no check that the caller is the designated Starkware sequencer. The spec explicitly restricts this function to "Only starkware sequencer," but the implementation omits that guard entirely. Because `last_reward_block` is a global, single-slot value that is written unconditionally at the start of the function, any unprivileged caller can advance it before the sequencer acts, permanently discarding all staker rewards for that block.

---

### Finding Description

`update_rewards` is the consensus-phase reward distribution entry point. The spec states its access control is "Only starkware sequencer."

The implementation at `src/staking/staking.cairo` lines 1449–1507:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ← NO caller identity check here
    ...
    self.last_reward_block.write(current_block_number);   // global slot written first

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits before distributing
    }
    // reward distribution follows
```

`last_reward_block` is a single global storage slot shared across all stakers. Once it is written to the current block number, every subsequent call in that block reverts with `REWARDS_ALREADY_UPDATED`. An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` before the sequencer:

1. Passes all guards (contract unpaused, staker exists and active, block advanced).
2. Writes `last_reward_block = current_block`.
3. Returns immediately via the `disable_rewards` branch — zero rewards distributed.
4. The sequencer's call for any staker in that block now reverts.

The rewards that would have been minted and distributed for that block are permanently lost; there is no recovery path.

Contrast with `update_rewards_from_attestation_contract`, which correctly enforces:

```cairo
assert!(
    get_caller_address() == self.attestation_contract.read(),
    "{}",
    Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
);
```

No equivalent guard exists in `update_rewards`.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

For every block in which the attacker front-runs the sequencer with `disable_rewards: true`, the entire epoch's block-reward allocation for all stakers is permanently discarded. The `last_reward_block` slot cannot be rewound; the sequencer cannot retry. Repeated execution across consecutive blocks eliminates all consensus-phase yield indefinitely.

---

### Likelihood Explanation

**High.** The function is part of the public ABI (`IStakingRewardsManager`), callable by any EOA or contract. No token balance, staking position, or privileged role is required — only a valid `staker_address` that is active and has passed the K-epoch delay. Such addresses are publicly enumerable via the `stakers` vector. The attack costs only gas and can be automated to fire every block.

---

### Recommendation

Add a sequencer-only guard at the top of `update_rewards`, mirroring the pattern used in `update_rewards_from_attestation_contract`:

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
    ...
```

If the sequencer address is not stored on-chain, an alternative is to use Starknet's `get_sequencer_address()` syscall directly.

---

### Proof of Concept

1. Consensus rewards are active (post `set_consensus_rewards_first_epoch` + K epochs).
2. Staker `S` is registered, active, and has passed the K-epoch balance delay.
3. Attacker calls `update_rewards(staker_address: S, disable_rewards: true)` at block `N`.
4. `last_reward_block` is set to `N`; function returns with no rewards distributed.
5. Sequencer calls `update_rewards(staker_address: S, disable_rewards: false)` at block `N` → reverts with `REWARDS_ALREADY_UPDATED`.
6. All stakers receive zero rewards for block `N`. Repeating every block eliminates all yield.

**Root cause lines:** [1](#0-0) 

**Spec access-control requirement (violated):** [2](#0-1) 

**Contrast — correctly guarded sibling function:** [3](#0-2) 

**Global `last_reward_block` written before reward distribution:** [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1380-1395)
```text
            let is_active_opt: Option<(Epoch, bool)> = self.btc_tokens.read(token_address);
            assert!(is_active_opt.is_some(), "{}", Error::TOKEN_NOT_EXISTS);
            let (is_active_first_epoch, is_active) = is_active_opt.unwrap();
            let curr_epoch = self.get_current_epoch();
            assert!(curr_epoch >= is_active_first_epoch, "{}", Error::INVALID_EPOCH);
            assert!(is_active, "{}", Error::TOKEN_ALREADY_DISABLED);
            let next_is_active_first_epoch = self.get_epoch_plus_k();
            self.btc_tokens.write(token_address, (next_is_active_first_epoch, false));
            self.emit(TokenManagerEvents::TokenDisabled { token_address });
        }
    }

    #[abi(embed_v0)]
    impl StakingAttestationImpl of IStakingAttestation<ContractState> {
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
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

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
