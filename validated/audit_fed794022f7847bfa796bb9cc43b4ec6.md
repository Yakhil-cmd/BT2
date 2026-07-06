### Title
Unbounded `stakers` Vector Growth Allows Attacker to Permanently Bloat `get_stakers()` Gas Cost - (File: `src/staking/staking.cairo`)

### Summary
An unprivileged attacker can spam-register many stakers (each with a distinct address and the minimum required stake) to permanently inflate the `stakers` storage vector. Because staker addresses are **never removed** from this vector even after a full `unstake_intent` → `unstake_action` cycle, and because `get_stakers()` iterates over the **entire** vector on every call, the attacker can make `get_stakers()` consume unbounded gas, eventually rendering it unusable by consensus clients.

### Finding Description

The `stakers` storage vector is append-only. Every successful `stake()` call pushes the caller's address onto it: [1](#0-0) 

The contract's own comment acknowledges this is permanent: [2](#0-1) 

`get_stakers()` iterates over the **full range** of this vector on every invocation, skipping inactive entries in-loop but still paying the storage-read cost for each one: [3](#0-2) 

`assert_staker_address_not_reused` prevents re-staking from the same address, but it does **not** prevent an attacker from using a fresh address each time: [4](#0-3) 

**Attack flow:**
1. Attacker funds N fresh addresses each with `min_stake` STRK.
2. Each address calls `stake()` → address is pushed to `stakers` vector.
3. Each address calls `unstake_intent()` then, after the exit window, `unstake_action()` → tokens are returned, but the address **remains** in `stakers` forever.
4. The attacker can recycle the same tokens across sequential addresses (stake → wait → unstake → move tokens to next address → repeat), so the only ongoing cost is gas per registration.
5. After N iterations, `get_stakers()` must read N storage slots on every call, regardless of how many are active.

### Impact Explanation

`get_stakers()` is the consensus-layer entrypoint that returns the validator set for a given epoch. It is called by the Starknet sequencer/consensus infrastructure. If the `stakers` vector is bloated to a sufficient size, `get_stakers()` will exceed the block gas limit and revert on every call, permanently freezing the ability to read the validator set. This matches the **Medium: Unbounded gas consumption** impact category.

### Likelihood Explanation

The attack requires only `min_stake` tokens per registered staker address and gas. Tokens are fully recoverable after the exit window, so the net cost per permanently-added vector entry is only gas. A moderately funded attacker can execute this over many epochs. The `min_stake` is configurable and can be set low, further reducing the barrier.

### Recommendation

1. **Prune inactive stakers from the vector** during `unstake_action()`, or use a separate active-staker count/set that is decremented on exit.
2. Alternatively, replace the `Vec` with an `IterableMap` keyed by staker address so that entries can be deleted, mirroring how `btc_tokens` is managed.
3. As a short-term mitigation, enforce a meaningful minimum stake that makes the attack economically prohibitive, and document the gas bound of `get_stakers()` as a function of the total number of ever-registered stakers.

### Proof of Concept

```
// Pseudocode – repeat for addresses addr_1 … addr_N
for i in 1..N:
    fund(addr_i, min_stake)
    stake(addr_i, reward=addr_i, operational=op_i, amount=min_stake)
    // addr_i is now in stakers[i]
    unstake_intent(addr_i)
    advance_time(exit_wait_window)
    unstake_action(addr_i)          // tokens returned; addr_i stays in stakers[]
    transfer(addr_i → addr_{i+1})   // recycle tokens

// Now get_stakers() must iterate over N entries, all inactive.
// At large N, the call reverts with out-of-gas.
```

The flow test `set_same_public_key_for_2_different_stakers_flow_test` already demonstrates that multiple independent stakers coexist in the vector and are all iterated by `get_stakers()`: [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L168-169)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L347-348)
```text
            // Add staker address to the stakers vector.
            self.stakers.push(staker_address);
```

**File:** src/staking/staking.cairo (L918-936)
```text
            for staker_address_ptr in self.stakers.into_iter_full_range() {
                let staker_address = staker_address_ptr.read();
                if !self.is_staker_active(:staker_address, :epoch_id) {
                    continue;
                }

                let staking_power = self
                    .get_staker_staking_power_at_epoch(
                        :staker_address, :epoch_id, :strk_total_stake, :btc_total_stake,
                    );
                if staking_power.is_zero() {
                    continue;
                }

                let public_key = self.get_public_key_at_epoch(:staker_address, :epoch_id);
                let peer_id = self.get_peer_id_at_epoch(:staker_address, :epoch_id);
                stakers.append((staker_address, staking_power, public_key, peer_id));
            }
            stakers.span()
```

**File:** src/staking/staking.cairo (L2204-2217)
```text
        fn assert_staker_address_not_reused(self: @ContractState, staker_address: ContractAddress) {
            // Catch stakers that entered in an older version (V0 or V1), and performed
            // `exit_action` in V1.
            assert!(
                self.staker_balance_trace.entry(key: staker_address).is_empty(),
                "{}",
                Error::STAKER_ADDRESS_ALREADY_USED_IN_V1,
            );
            assert!(
                self.staker_own_balance_trace.entry(key: staker_address).is_empty(),
                "{}",
                Error::STAKER_ADDRESS_ALREADY_USED,
            );
        }
```

**File:** src/flow_test/test.cairo (L1848-1884)
```text
fn set_same_public_key_for_2_different_stakers_flow_test() {
    let cfg: StakingInitConfig = Default::default();
    let amount = cfg.staking_contract_info.min_stake;
    let mut system = SystemConfigTrait::basic_stake_flow_cfg(:cfg).deploy();
    let staker_1 = system.new_staker(:amount);
    let staker_2 = system.new_staker(:amount);
    let public_key = PUBLIC_KEY;
    let staking_address = system.staking.address;
    let staking = system.staking.dispatcher();
    let staking_consensus = system.staking.consensus_dispatcher();

    // Staker 1 stake and set public key.
    system.stake(staker: staker_1, :amount, pool_enabled: false, commission: 200);
    cheat_caller_address_once(
        contract_address: staking_address, caller_address: staker_1.staker.address,
    );
    staking.set_public_key(:public_key);

    // Staker 2 stake and set public key.
    system.stake(staker: staker_2, :amount, pool_enabled: false, commission: 200);
    cheat_caller_address_once(
        contract_address: staking_address, caller_address: staker_2.staker.address,
    );
    staking.set_public_key(:public_key);

    // Test get_stakers.
    system.advance_k_epochs();
    let expected_stakers = array![
        (staker_1.staker.address, STRK_WEIGHT_FACTOR / 2, Option::Some(public_key), Option::None),
        (staker_2.staker.address, STRK_WEIGHT_FACTOR / 2, Option::Some(public_key), Option::None),
    ]
        .span();
    let epoch_id = staking.get_current_epoch();
    assert!(staking_consensus.get_stakers(:epoch_id) == expected_stakers);
    assert!(staking.get_current_public_key(staker_address: staker_1.staker.address) == public_key);
    assert!(staking.get_current_public_key(staker_address: staker_2.staker.address) == public_key);
}
```
