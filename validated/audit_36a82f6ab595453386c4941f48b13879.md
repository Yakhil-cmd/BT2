### Title
Unprotected `declare_operational_address` Allows Anyone to Emit Fraudulent `OperationalAddressDeclared` Events with Arbitrary Staker Addresses - (File: src/staking/staking.cairo)

### Summary
`declare_operational_address` in `src/staking/staking.cairo` accepts a caller-supplied `staker_address` parameter with no validation that the address corresponds to an existing staker. Any unprivileged caller can invoke this function repeatedly with arbitrary `staker_address` values, emitting a flood of fraudulent `OperationalAddressDeclared` events and polluting the `eligible_operational_addresses` storage map with attacker-controlled entries.

### Finding Description
The function `declare_operational_address` is part of the two-step operational address change flow: an intended new operational address first declares itself eligible for a staker, then the staker calls `change_operational_address` to complete the swap.

The implementation is:

```cairo
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

The only guards are:
1. The caller's address must not already be an active operational address (`operational_address_to_staker_address` is zero).
2. The caller's address must not be a registered token.

There is **no check** that `staker_address` is a valid, existing staker. An attacker using any fresh address (not yet assigned as an operational address) can pass any `ContractAddress` — including zero, non-existent accounts, or real staker addresses — as `staker_address`, causing the event `OperationalAddressDeclared { operational_address: attacker_addr, staker_address: victim }` to be emitted and the mapping `eligible_operational_addresses[attacker_addr] = victim` to be written.

By using many fresh addresses (Starknet account deployment is cheap), an attacker can emit an unbounded number of fraudulent `OperationalAddressDeclared` events referencing arbitrary staker addresses.

### Impact Explanation
Off-chain infrastructure (indexers, monitoring dashboards, staker UIs, alerting systems) that consume `OperationalAddressDeclared` events to track pending operational address changes will be flooded with fraudulent entries. This can:
- Cause indexers to process unbounded spurious state updates, leading to unbounded gas consumption on the indexer side and potential service degradation.
- Mislead stakers or delegators reading event logs into believing a large number of operational address changes are pending for their staker address.
- Pollute the `eligible_operational_addresses` storage map with attacker-controlled entries, though these entries are harmless on-chain since the staker must still explicitly call `change_operational_address` to act on them.

This matches the **Medium** impact: griefing with no profit motive but damage to users or protocol (off-chain infrastructure DoS, misleading event consumers).

### Likelihood Explanation
The attack requires no special privileges, no funds, and no existing staker relationship. Any address that has not previously been registered as an operational address can call `declare_operational_address` with any `staker_address`. Starknet account deployment is inexpensive, so an attacker can generate many fresh addresses to bypass the single-use-per-address constraint. Likelihood is **high** for a motivated griefing attacker.

### Recommendation
Add a validation that `staker_address` corresponds to an existing staker before writing to storage and emitting the event:

```cairo
// Assert the target staker exists before proceeding.
assert!(self.staker_info.read(staker_address).is_some(), "{}", Error::STAKER_NOT_EXISTS);
```

This ensures `OperationalAddressDeclared` events are only emitted for real stakers, eliminating the griefing vector.

### Proof of Concept

1. Attacker generates a fresh address `attacker_addr` (not yet an operational address for any staker).
2. Attacker calls `declare_operational_address(victim_staker_address)` from `attacker_addr`, where `victim_staker_address` is any real or fake address.
3. The function passes all guards (attacker address is not in use, not a token), writes `eligible_operational_addresses[attacker_addr] = victim_staker_address`, and emits `OperationalAddressDeclared { operational_address: attacker_addr, staker_address: victim_staker_address }`.
4. Attacker repeats with thousands of fresh addresses, each time passing a different (or the same) `staker_address`, emitting thousands of fraudulent events.
5. Off-chain indexers processing `OperationalAddressDeclared` events are flooded, consuming unbounded resources and surfacing misleading pending-change notifications to staker UIs.

Relevant code: [1](#0-0) 

Event definition showing both fields are indexed and consumed by off-chain tooling: [2](#0-1)

### Citations

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

**File:** src/staking/interface.cairo (L386-391)
```text
    pub struct OperationalAddressDeclared {
        #[key]
        pub operational_address: ContractAddress,
        #[key]
        pub staker_address: ContractAddress,
    }
```
