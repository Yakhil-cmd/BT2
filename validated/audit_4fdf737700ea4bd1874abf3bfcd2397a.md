### Title
Attacker Can Permanently Block a Staker from Completing `change_operational_address` by Front-Running `declare_operational_address` - (File: `src/staking/staking.cairo`)

### Summary

The two-step operational address rotation flow (`declare_operational_address` → `change_operational_address`) contains a griefing vulnerability. After a new operational address declares itself eligible for a staker, any attacker with `min_stake` STRK can call `stake()` using that same address as their own operational address, causing the victim staker's subsequent `change_operational_address` call to permanently revert with `OPERATIONAL_EXISTS`.

### Finding Description

Changing a staker's operational address requires two steps:

1. **Step 1** — The new operational address calls `declare_operational_address(staker_address)`, which writes `eligible_operational_addresses[new_op_addr] = staker_address`.
2. **Step 2** — The staker calls `change_operational_address(new_op_addr)`, which checks that `new_op_addr` is not already registered as another staker's operational address.

The guard in Step 2 is:

```cairo
assert!(
    self.operational_address_to_staker_address.read(operational_address).is_zero(),
    "{}",
    Error::OPERATIONAL_EXISTS,
);
``` [1](#0-0) 

However, `stake()` allows **any caller** to register **any unused address** as their operational address without any prior declaration:

```cairo
assert!(
    self.operational_address_to_staker_address.read(operational_address).is_zero(),
    "{}",
    Error::OPERATIONAL_EXISTS,
);
``` [2](#0-1) 

`stake()` never consults `eligible_operational_addresses`. This means an attacker who observes a `declare_operational_address` transaction in the mempool can back-run it with `stake(attacker_reward_addr, new_op_addr, min_stake)`, atomically occupying `new_op_addr` in `operational_address_to_staker_address`. The victim staker's subsequent `change_operational_address(new_op_addr)` then reverts unconditionally.

The attacker can maintain the block indefinitely by keeping their stake active, or repeat the attack each time the victim picks a new target address.

### Impact Explanation

The staker is permanently prevented from rotating their operational address to the desired key. The operational address is the key used for on-chain attestations. If the staker's current operational key is compromised or unavailable, they cannot rotate it, causing missed attestations and loss of attestation-based rewards. This constitutes **griefing with no profit motive but concrete damage to the staker** (missed yield).

This matches the allowed impact: **Medium — Griefing with no profit motive but damage to users or protocol**.

### Likelihood Explanation

- The attack entry point is fully permissionless: any address with `min_stake` STRK can call `stake()`.
- The attacker only needs to monitor the public mempool for `declare_operational_address` events and back-run them.
- The attacker's capital is recoverable after the exit window, so the net cost is only gas and the opportunity cost of locked STRK.
- The attack can be repeated indefinitely against any target address the victim chooses.

### Recommendation

In `change_operational_address`, when `operational_address_to_staker_address[operational_address]` is non-zero, verify whether the occupying staker is the same as the caller (i.e., the address is already the caller's own operational address — a no-op). More importantly, the check should be relaxed analogously to the original report's fix: if the address is already registered but the `eligible_operational_addresses` mapping still points to the calling staker, the contract should proceed (or evict the conflicting registration). Alternatively, reserve the operational address at `declare_operational_address` time by writing a placeholder into `operational_address_to_staker_address`, preventing any third party from racing to claim it between the two steps.

### Proof of Concept

1. `new_op_addr` broadcasts `declare_operational_address(staker_A)`. [3](#0-2) 

2. Attacker observes the transaction in the mempool and back-runs with:
   ```
   stake(attacker_reward_addr, new_op_addr, min_stake)
   ```
   This succeeds because `operational_address_to_staker_address[new_op_addr]` is still zero at this point. [4](#0-3) 

3. `staker_A` calls `change_operational_address(new_op_addr)`. The assertion at line 670–674 now reads a non-zero value and reverts with `"Operational address already exists"`. [5](#0-4) 

4. The attacker calls `unstake_intent()` and, after the exit window, recovers their STRK. The attack cost is only gas and the exit-window lock-up period. The victim staker is permanently blocked from using `new_op_addr` as long as the attacker keeps their stake active, and must choose a new target address — which can be attacked again in the same way.

### Citations

**File:** src/staking/staking.cairo (L298-342)
```text
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_EXISTS,
            );
            self.assert_staker_address_not_reused(:staker_address);
            assert!(
                !self.does_token_exist(token_address: staker_address), "{}", Error::STAKER_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            assert!(amount >= self.min_stake.read(), "{}", Error::AMOUNT_LESS_THAN_MIN_STAKE);
            let normalized_amount = NormalizedAmountTrait::from_strk_native_amount(:amount);

            // Transfer funds from staker. Sufficient approvals is a pre-condition.
            let staking_contract = get_contract_address();
            let token_dispatcher = strk_token_dispatcher();
            token_dispatcher
                .checked_transfer_from(
                    sender: staker_address, recipient: staking_contract, amount: amount.into(),
                );

            self
                .initialize_staker_own_balance_trace(
                    :staker_address, own_balance: normalized_amount,
                );

            // Create the record for the staker.
            self
                .staker_info
                .write(
                    staker_address,
                    VInternalStakerInfoTrait::new_latest(:reward_address, :operational_address),
                );

            // Update the operational address mapping, which is a 1 to 1 mapping.
            self.operational_address_to_staker_address.write(operational_address, staker_address);
```

**File:** src/staking/staking.cairo (L665-687)
```text
        fn change_operational_address(
            ref self: ContractState, operational_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_EXISTS,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            let staker_address = get_caller_address();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            assert!(
                self.eligible_operational_addresses.read(operational_address) == staker_address,
                "{}",
                Error::OPERATIONAL_NOT_ELIGIBLE,
            );
```

**File:** src/staking/staking.cairo (L705-722)
```text
        fn declare_operational_address(ref self: ContractState, staker_address: ContractAddress) {
            self.general_prerequisites();
            let operational_address = get_caller_address();
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_IN_USE,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            if self.eligible_operational_addresses.read(operational_address) == staker_address {
                return;
            }
            self.eligible_operational_addresses.write(operational_address, staker_address);
            self.emit(Events::OperationalAddressDeclared { operational_address, staker_address });
```
