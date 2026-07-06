### Title
Staker Can Manipulate Attestation Target Block by Adjusting Stake K Epochs in Advance - (File: src/attestation/attestation.cairo)

### Summary

The `_calculate_target_attestation_block` function uses the staker's current-epoch `stake` amount as an input to the Poseidon hash that determines the pseudo-random attestation target block. Because stake changes take effect after K epochs, a staker can call `increase_stake` exactly K epochs before a target epoch to steer the hash output toward any desired block offset, defeating the liveness-randomization guarantee of the attestation mechanism.

### Finding Description

`_calculate_target_attestation_block` computes:

```
hash = Poseidon(stake, epoch_id, staker_address)
block_offset = hash % (epoch_len - attestation_window)
target_block = epoch_start_block + block_offset
``` [1](#0-0) 

The `stake` field is populated by `get_attestation_info_by_operational_address`, which reads the staker's total STRK balance **at the current epoch** via the balance-trace mechanism: [2](#0-1) 

Because the balance trace enforces a K-epoch delay before stake changes become effective, a staker who calls `increase_stake` in epoch `N-K` will see that new balance reflected in epoch `N`'s attestation hash. `increase_stake` is callable by the staker address or their reward address with no privileged role required: [3](#0-2) 

**Attack steps:**

1. At epoch `N-K`, the attacker iterates over candidate `delta` values and computes `Poseidon(current_stake + delta, N, staker_address) % (epoch_len - attestation_window)` off-chain.
2. They find a `delta` such that the resulting `target_block` falls in a window they control — e.g., the very beginning of epoch `N` (offset ≈ 0), so the valid attestation window opens at `epoch_start_block + MIN_ATTESTATION_WINDOW` (block 11 of the epoch).
3. They call `increase_stake(staker_address, delta)` in epoch `N-K`.
4. When epoch `N` begins, they wait until block 11, fetch the hash of `target_block` from any public RPC, and call `attest(block_hash)`.
5. `update_rewards_from_attestation_contract` is triggered, crediting a full epoch of rewards. [4](#0-3) 

The staker never needs to be running a validator node; they only need to submit one transaction at a self-chosen, pre-computed time.

### Impact Explanation

The attestation mechanism is the sole liveness gate in the pre-consensus reward model (`is_pre_consensus()` path). Successful attestation unconditionally triggers `update_rewards_from_attestation_contract`, which calculates and credits a full epoch's staking rewards to the staker and their delegation pool. [5](#0-4) 

A staker who is not operating a node can claim rewards every epoch by manipulating their stake K epochs in advance. This constitutes **theft of unclaimed yield** — a High-severity impact under the allowed scope.

### Likelihood Explanation

- `increase_stake` is a standard, permissionless operation available to any active staker or their reward address.
- The Poseidon hash space is 252 bits, but the modulus is only `epoch_len - attestation_window` (a small integer, e.g. 20–200 blocks). The attacker needs to find a `delta` such that `hash % modulus` lands in a window of size `attestation_window - MIN_ATTESTATION_WINDOW`. For typical parameters this succeeds with probability ~45% per candidate, so on average 2–3 candidates suffice.
- The only cost is the token amount of `delta` (locked, not lost) and one extra transaction K epochs before the target epoch.
- No privileged access, leaked keys, or external dependencies are required.

### Recommendation

Remove `stake` from the attestation hash inputs. The target block should depend only on values that cannot be manipulated by the staker: `staker_address` and `epoch_id` are sufficient to produce a per-staker, per-epoch pseudo-random offset. Alternatively, commit to the target block at epoch start using a value the staker cannot influence (e.g., the epoch's starting block hash), and reveal it only after the epoch begins. [6](#0-5) 

### Proof of Concept

```
Assume: epoch_len = 40, attestation_window = 20, MIN_ATTESTATION_WINDOW = 11, K = 2
Staker address = 0xABCD, current stake = S

Epoch N-2 (planning phase):
  For delta in [1, 2, 3, ...]:
    candidate_stake = S + delta
    hash = Poseidon(candidate_stake, N, 0xABCD)
    offset = hash % (40 - 20)   // modulus = 20
    if offset <= 2:              // target block is within first 2 blocks of epoch
      call increase_stake(staker_address=0xABCD, amount=delta)
      break

Epoch N, block epoch_start + 11:
  target_block = epoch_start + offset   // offset ≤ 2, so target_block is in the past
  block_hash = rpc.get_block_hash(target_block)   // no node required
  call attest(block_hash)
  // → _assert_attest_in_window passes: target_block+11 ≤ current ≤ target_block+20
  // → update_rewards_from_attestation_contract credits full epoch rewards
```

The staker collects rewards for epoch N without ever running a validator node.

### Citations

**File:** src/attestation/attestation.cairo (L116-135)
```text
        fn attest(ref self: ContractState, block_hash: felt252) {
            let operational_address = get_caller_address();
            let staking_dispatcher = IStakingAttestationDispatcher {
                contract_address: self.staking_contract.read(),
            };
            // Note: This function checks for a zero staker address and will panic if so.
            let staking_attestation_info = staking_dispatcher
                .get_attestation_info_by_operational_address(:operational_address);
            self._validate_attestation(:block_hash, :staking_attestation_info);
            // Work is one tx per epoch.
            self
                ._mark_attestation_is_done(
                    staker_address: staking_attestation_info.staker_address(),
                    current_epoch: staking_attestation_info.epoch_id(),
                );
            staking_dispatcher
                .update_rewards_from_attestation_contract(
                    staker_address: staking_attestation_info.staker_address(),
                );
        }
```

**File:** src/attestation/attestation.cairo (L221-238)
```text
        fn _calculate_target_attestation_block(
            self: @ContractState, staking_attestation_info: StakingAttestationInfo,
        ) -> BlockNumber {
            // Compute staker hash for the attestation.
            let hash = PoseidonTrait::new()
                .update(staking_attestation_info.stake().into())
                .update(staking_attestation_info.epoch_id().into())
                .update(staking_attestation_info.staker_address().into())
                .finalize();
            // Calculate staker's block number in this epoch.
            let attestation_window = self.attestation_window.read();
            let block_offset: u256 = hash
                .into() % (staking_attestation_info.epoch_len() - attestation_window.into())
                .into();
            // Calculate actual block number for attestation.
            let target_attestation_block = staking_attestation_info.current_epoch_starting_block()
                + block_offset.try_into().unwrap();
            target_attestation_block
```

**File:** src/staking/staking.cairo (L368-409)
```text
        fn increase_stake(
            ref self: ContractState, staker_address: ContractAddress, amount: Amount,
        ) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let caller_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            assert!(
                caller_address == staker_address || caller_address == staker_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_INCREASE_STAKE,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let normalized_amount = NormalizedAmountTrait::from_strk_native_amount(:amount);

            // Transfer funds from caller (which is either the staker or their reward address).
            let staking_contract_address = get_contract_address();
            let token_dispatcher = strk_token_dispatcher();
            token_dispatcher
                .checked_transfer_from(
                    sender: caller_address,
                    recipient: staking_contract_address,
                    amount: amount.into(),
                );

            // Update staker's staked amount, and total stake.
            let (normalized_old_self_stake, normalized_new_self_stake) = self
                .increase_staker_own_amount(:staker_address, amount: normalized_amount);

            // Emit events.
            let new_self_stake = normalized_new_self_stake.to_strk_native_amount();
            self
                .emit(
                    Events::StakeOwnBalanceChanged {
                        staker_address,
                        old_self_stake: normalized_old_self_stake.to_strk_native_amount(),
                        new_self_stake,
                    },
                );
            new_self_stake
        }
```

**File:** src/staking/staking.cairo (L1394-1423)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            // Get current epoch data.
            let (strk_epoch_rewards, btc_epoch_rewards) = reward_supplier_dispatcher
                .calculate_current_epoch_rewards();
            let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let curr_epoch = self.get_current_epoch();
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_epoch_rewards,
                    btc_total_rewards: btc_epoch_rewards,
                    :strk_total_stake,
                    :btc_total_stake,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
```

**File:** src/staking/staking.cairo (L1436-1443)
```text
            let stake = self
                .get_staker_total_strk_balance_at_epoch(
                    :staker_address, :staker_pool_info, :epoch_id,
                )
                .to_strk_native_amount();
            AttestationInfoTrait::new(
                :staker_address, :stake, :epoch_len, :epoch_id, :current_epoch_starting_block,
            )
```
