### Title
Stale `eligible_operational_addresses` Approval Not Cleared After `change_operational_address` Execution - (File: src/staking/staking.cairo)

### Summary

`change_operational_address` consumes the pre-approval stored in `eligible_operational_addresses` but never clears it. The stale entry persists indefinitely, allowing a staker to re-claim a previously-used operational address without the address owner's renewed consent, enabling a persistent griefing loop.

### Finding Description

The `declare_operational_address` / `change_operational_address` flow is a two-step consent mechanism: the operational address must first call `declare_operational_address` to write its consent into `eligible_operational_addresses`, and then the staker calls `change_operational_address` to consume that consent and activate the address.

In `change_operational_address`, the function verifies the consent and updates `operational_address_to_staker_address`, but **never clears** `eligible_operational_addresses[operational_address]`:

```cairo
// Set operational address and write to storage.
let old_address = staker_info.operational_address;
self.operational_address_to_staker_address.write(old_address, Zero::zero());
staker_info.operational_address = operational_address;
self.write_staker_info(:staker_address, :staker_info);
self.operational_address_to_staker_address.write(operational_address, staker_address);
// ← eligible_operational_addresses[operational_address] is NEVER zeroed
``` [1](#0-0) 

Compare this to `declare_operational_address`, which explicitly checks the same mapping to gate consent:

```cairo
assert!(
    self.eligible_operational_addresses.read(operational_address) == staker_address,
    "{}",
    Error::OPERATIONAL_NOT_ELIGIBLE,
);
``` [2](#0-1) 

**Attack scenario:**

1. `O1` calls `declare_operational_address(staker_A)` → `eligible_operational_addresses[O1] = staker_A`
2. `staker_A` calls `change_operational_address(O1)` → `operational_address_to_staker_address[O1] = staker_A`; stale entry `eligible_operational_addresses[O1] = staker_A` remains.
3. `staker_A` later changes to `O2` → `operational_address_to_staker_address[O1] = 0` (freed); stale entry still present.
4. `staker_A` immediately calls `change_operational_address(O1)` again — both checks pass (`O1` is free in `operational_address_to_staker_address`, and `eligible_operational_addresses[O1]` still equals `staker_A`) — **without `O1` ever re-consenting**.
5. `O1` is now re-bound to `staker_A`. While bound, `O1` cannot call `declare_operational_address` to revoke, because `declare_operational_address` checks `operational_address_to_staker_address.read(operational_address).is_zero()` and reverts with `OPERATIONAL_IN_USE`. [3](#0-2) 

Steps 3–4 can be repeated indefinitely, trapping `O1` in a griefing loop.

### Impact Explanation

`O1` is permanently forced to remain `staker_A`'s operational address. Because `declare_operational_address` reverts with `OPERATIONAL_IN_USE` while `O1` is active, `O1` has no on-chain escape path as long as `staker_A` front-runs every release with an immediate re-claim. Any third-party staker (`staker_B`) that intended to use `O1` as their operational address is also blocked, since `change_operational_address` reverts with `OPERATIONAL_EXISTS` when the address is already bound.

This matches the **Medium** impact tier: griefing with no profit motive but concrete damage to users (the operational address owner and any staker depending on it).

### Likelihood Explanation

The attacker is an existing staker who previously used the target operational address. No privileged role is required. The attack is executable by any staker who monitors the chain for the moment their old operational address is freed, then front-runs the victim's `declare_operational_address` revocation call. On Starknet, transaction ordering is controlled by the sequencer, making front-running feasible for a motivated attacker.

### Recommendation

Clear the stale approval inside `change_operational_address` immediately after the eligibility check passes:

```cairo
// After verifying eligibility, clear the consumed approval.
self.eligible_operational_addresses.write(operational_address, Zero::zero());
```

This mirrors the pattern used in `remove_staker`, which explicitly zeroes `operational_address_to_staker_address` for the old address, and is consistent with the principle that a one-time consent should be consumed on use. [4](#0-3) 

### Proof of Concept

```
1. staker_A is registered with operational_address = O_initial.
2. O1 calls declare_operational_address(staker_A).
   → eligible_operational_addresses[O1] = staker_A
3. staker_A calls change_operational_address(O1).
   → operational_address_to_staker_address[O1] = staker_A
   → eligible_operational_addresses[O1] = staker_A  ← NOT cleared
4. staker_A calls declare_operational_address for O2, then change_operational_address(O2).
   → operational_address_to_staker_address[O1] = 0  (freed)
   → eligible_operational_addresses[O1] = staker_A  ← still stale
5. staker_A calls change_operational_address(O1).
   Check 1: operational_address_to_staker_address[O1] == 0  ✓
   Check 2: eligible_operational_addresses[O1] == staker_A  ✓
   → O1 is re-bound to staker_A with NO new consent from O1.
6. O1 attempts declare_operational_address(0) to revoke.
   → Fails: OPERATIONAL_IN_USE (operational_address_to_staker_address[O1] != 0)
7. Repeat steps 4–6 indefinitely to trap O1.
```

### Citations

**File:** src/staking/staking.cairo (L683-687)
```text
            assert!(
                self.eligible_operational_addresses.read(operational_address) == staker_address,
                "{}",
                Error::OPERATIONAL_NOT_ELIGIBLE,
            );
```

**File:** src/staking/staking.cairo (L689-694)
```text
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
