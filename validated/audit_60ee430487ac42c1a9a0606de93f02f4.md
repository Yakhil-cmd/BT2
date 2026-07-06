### Title
Operational Address Front-Running in `stake()` Allows Griefing of New Stakers - (File: src/staking/staking.cairo)

---

### Summary

The `stake()` function assigns an operational address without requiring prior consent from that address. A malicious actor who observes a pending `stake()` transaction can front-run it by submitting their own `stake()` with the same `operational_address`, causing the victim's transaction to revert with `OPERATIONAL_EXISTS` and permanently blocking the victim from using that specific operational address as long as the attacker remains staked.

---

### Finding Description

The Starknet Staking contract implements a two-step consent mechanism for changing an operational address post-staking:

1. The operational address calls `declare_operational_address(staker_address)` to consent.
2. The staker calls `change_operational_address(operational_address)` which enforces the consent check. [1](#0-0) 

However, the initial `stake()` function bypasses this consent mechanism entirely. It only checks that the operational address is not already in use, then directly assigns it: [2](#0-1) [3](#0-2) 

There is no check against `eligible_operational_addresses` in `stake()`. Any caller who submits a `stake()` transaction with a target operational address before the legitimate staker's transaction is included will claim that address, causing the legitimate staker's transaction to revert. [4](#0-3) 

---

### Impact Explanation

**Medium — Griefing with no profit motive but damage to users.**

A staker who has configured a specific operational address (e.g., a dedicated attestation key, a hardware-secured key, or a well-known validator identity) can be permanently blocked from using it. As long as the attacker remains staked, the operational address is locked to the attacker's staker record. The victim must either wait for the attacker to voluntarily unstake (after the full exit wait window) or abandon the intended operational address entirely and reconfigure their attestation infrastructure. [5](#0-4) 

---

### Likelihood Explanation

**Low-Medium.** Starknet's gateway exposes pending transactions, making mempool observation feasible. The attacker must hold sufficient funds to meet `min_stake`, which is a real cost, but the attack can be executed with no financial gain motive (pure griefing). The attack is most impactful against well-known validators whose intended operational addresses are predictable or publicly announced. [6](#0-5) 

---

### Recommendation

Apply the same consent-based two-step pattern to `stake()` that is already enforced in `change_operational_address()`. Specifically, require that the `operational_address` has previously called `declare_operational_address(staker_address)` before `stake()` can assign it:

```cairo
assert!(
    self.eligible_operational_addresses.read(operational_address) == staker_address,
    "{}",
    Error::OPERATIONAL_NOT_ELIGIBLE,
);
```

This mirrors the existing guard in `change_operational_address()` and closes the inconsistency. [7](#0-6) 

---

### Proof of Concept

1. Staker A controls operational address `O` and submits `stake(reward_A, O, amount_A)` to the Starknet gateway.
2. Attacker B observes the pending transaction via the gateway API.
3. Attacker B submits `stake(reward_B, O, amount_B)` with a higher fee, causing the sequencer to include B's transaction first.
4. B's `stake()` passes the only relevant check (`operational_address_to_staker_address[O].is_zero()` → true) and writes `operational_address_to_staker_address[O] = B`.
5. A's `stake()` now fails: `operational_address_to_staker_address[O]` is non-zero → `OPERATIONAL_EXISTS` revert.
6. Address `O` is now locked to staker B. Staker A cannot use `O` until B calls `unstake_intent()` and waits the full exit window, or B is ragekicked — neither of which A can force. [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L288-366)
```text
        fn stake(
            ref self: ContractState,
            reward_address: ContractAddress,
            operational_address: ContractAddress,
            amount: Amount,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            assert!(self.staker_info.read(staker_address).is_none(), "{}", Error::STAKER_EXISTS);
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

            // Update total stake.
            self.add_to_total_stake(token_address: STRK_TOKEN_ADDRESS, amount: normalized_amount);

            // Add staker address to the stakers vector.
            self.stakers.push(staker_address);

            // Mark the staker's version.
            self.staker_version.write(staker_address, LATEST_STAKER_VERSION);

            // Emit events.
            self
                .emit(
                    Events::NewStaker {
                        staker_address, reward_address, operational_address, self_stake: amount,
                    },
                );
            self
                .emit(
                    Events::StakeOwnBalanceChanged {
                        staker_address, old_self_stake: Zero::zero(), new_self_stake: amount,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L665-703)
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

            // Set operational address and write to storage.
            let old_address = staker_info.operational_address;
            self.operational_address_to_staker_address.write(old_address, Zero::zero());
            staker_info.operational_address = operational_address;
            self.write_staker_info(:staker_address, :staker_info);
            self.operational_address_to_staker_address.write(operational_address, staker_address);

            // Emit event.
            self
                .emit(
                    Events::OperationalAddressChanged {
                        staker_address, new_address: operational_address, old_address,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L705-723)
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
        }
```
