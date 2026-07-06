### Title
Operational Address Griefing via `declare_operational_address` Event Observation — (`File: src/staking/staking.cairo`)

---

### Summary

An unprivileged attacker can permanently prevent a staker from adopting a specific operational address by observing the public `OperationalAddressDeclared` event and racing to call `stake` with that same operational address before the victim calls `change_operational_address`. The `stake` function imposes no eligibility check against `eligible_operational_addresses`, so any caller can claim any not-yet-active operational address as their own.

---

### Finding Description

The two-step operational-address-change flow is:

1. The desired operational address calls `declare_operational_address(staker_A)`, writing `eligible_operational_addresses[op_addr] = staker_A` and emitting `OperationalAddressDeclared { operational_address: op_addr, staker_address: staker_A }`.
2. `staker_A` calls `change_operational_address(op_addr)`, which verifies `eligible_operational_addresses[op_addr] == staker_A` before committing.

The `declare_operational_address` function:

```cairo
fn declare_operational_address(ref self: ContractState, staker_address: ContractAddress) {
    self.general_prerequisites();
    let operational_address = get_caller_address();
    assert!(
        self.operational_address_to_staker_address.read(operational_address).is_zero(), ...
    );
    ...
    self.eligible_operational_addresses.write(operational_address, staker_address);
    self.emit(Events::OperationalAddressDeclared { operational_address, staker_address });
}
```

The emitted event is fully public. An attacker who observes it immediately knows that `op_addr` is not yet registered in `operational_address_to_staker_address` (the function asserts this at line 709) and that `staker_A` intends to use it.

The `stake` function only checks that the operational address is not already active:

```cairo
assert!(
    self.operational_address_to_staker_address.read(operational_address).is_zero(),
    "{}",
    Error::OPERATIONAL_EXISTS,
);
```

It does **not** consult `eligible_operational_addresses`. Therefore the attacker can immediately call:

```cairo
stake(attacker_reward_address, op_addr, min_stake)
```

This writes `operational_address_to_staker_address[op_addr] = attacker_address`. When `staker_A` subsequently calls `change_operational_address(op_addr)`, it reverts with `OPERATIONAL_EXISTS` at line 671–674.

The attacker can repeat this for every new operational address `staker_A` attempts to declare, indefinitely blocking the address rotation.

---

### Impact Explanation

**Medium — Griefing with no profit motive but damage to users or protocol.**

The victim staker is permanently unable to rotate to any specific operational address of their choice. Because Starknet validators use the operational address for attestation duties, an inability to rotate a compromised or retiring operational key is a meaningful operational harm. The victim is not deprived of funds, but their ability to manage their validator identity is continuously disrupted. The attacker earns normal staking rewards on their `min_stake` deposit, so the net cost is only the opportunity cost of the exit wait window.

---

### Likelihood Explanation

`OperationalAddressDeclared` events are emitted on-chain and are trivially observable by any off-chain monitor. Starknet's sequencer model does not eliminate transaction-ordering races between the `declare_operational_address` confirmation and the victim's subsequent `change_operational_address` call; the window is at least one block. The attacker needs only `min_stake` STRK (recoverable after the exit wait window) and a simple event-watching bot. No privileged access, leaked keys, or external dependencies are required.

---

### Recommendation

In `stake`, add a check that rejects an `operational_address` that has already been declared eligible for a *different* staker:

```cairo
let declared_for = self.eligible_operational_addresses.read(operational_address);
assert!(
    declared_for.is_zero() || declared_for == staker_address,
    "{}",
    Error::OPERATIONAL_DECLARED_FOR_OTHER,
);
```

Alternatively, require that `stake` itself go through the same `declare_operational_address` pre-commitment step that `change_operational_address` already enforces, so that the operational address must have explicitly declared consent for the calling staker before it can be registered.

---

### Proof of Concept

1. **Setup**: `staker_A` is an existing staker. `op_addr` is a fresh address they wish to rotate to.

2. **Step 1 — Victim declares**: `op_addr` calls `declare_operational_address(staker_A)`.
   - `eligible_operational_addresses[op_addr] = staker_A`
   - Event `OperationalAddressDeclared { op_addr, staker_A }` is emitted on-chain.
   - At this point `operational_address_to_staker_address[op_addr]` is still zero (asserted by the function at line 709).

3. **Step 2 — Attacker races**: Attacker observes the event and calls `stake(attacker_reward, op_addr, min_stake)`.
   - Line 298–302: `operational_address_to_staker_address[op_addr].is_zero()` → passes.
   - No check against `eligible_operational_addresses` → passes.
   - Line 342: `operational_address_to_staker_address[op_addr] = attacker_address` is written.

4. **Step 3 — Victim blocked**: `staker_A` calls `change_operational_address(op_addr)`.
   - Line 671–674: `operational_address_to_staker_address[op_addr]` is now `attacker_address` (non-zero) → reverts with `OPERATIONAL_EXISTS`.

5. **Repeat**: Attacker repeats for every new `op_addr` `staker_A` tries to declare, at a cost of `min_stake` STRK per address (recoverable after 1 week).

**Relevant code locations:**

- `declare_operational_address` (emits the observable signal): [1](#0-0) 

- `stake` (missing eligibility guard, allows attacker to claim `op_addr`): [2](#0-1) 

- `change_operational_address` (victim's call that fails): [3](#0-2) 

- `eligible_operational_addresses` storage map: [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L125-126)
```text
        /// Map potential operational address to eligible staker address.
        eligible_operational_addresses: Map<ContractAddress, ContractAddress>,
```

**File:** src/staking/staking.cairo (L298-302)
```text
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_EXISTS,
            );
```

**File:** src/staking/staking.cairo (L665-694)
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
