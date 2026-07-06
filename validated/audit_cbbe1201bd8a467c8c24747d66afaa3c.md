Looking at the external report's vulnerability class — **pending/eligible state not cleared after the operation that consumes it** — I need to find an analog in the Starknet Staking codebase where a "consent" or "pending" mapping survives after the action that should exhaust it, allowing unauthorized re-execution.

The two-step operational address change flow is the direct analog:

1. `declare_operational_address(staker_address)` — called by the operational address to write consent into `eligible_operational_addresses[op_addr] = staker_addr`
2. `change_operational_address(operational_address)` — called by the staker, reads and validates the consent, but **never clears it** [1](#0-0) 

After `change_operational_address` completes, `eligible_operational_addresses[op_addr]` still equals `staker_addr`. When the staker later switches to a different operational address, the old one is freed (`operational_address_to_staker_address` is zeroed), but the stale consent entry remains. The staker can then call `change_operational_address` with the old address again — both guards pass — without the operational address ever re-declaring. [2](#0-1) 

`remove_staker` also does not clear `eligible_operational_addresses`, confirming no other code path cleans it up.

---

### Title
Stale `eligible_operational_addresses` Entry Allows Staker to Re-Claim Operational Address Without Re-Declaration — (`src/staking/staking.cairo`)

### Summary
`change_operational_address` consumes the consent stored in `eligible_operational_addresses` but never deletes it. After a staker switches away from an operational address, the stale entry lets the staker forcibly re-associate that address with themselves at any time, without the operational address's knowledge or re-consent.

### Finding Description
`declare_operational_address` writes a one-time consent:

```cairo
self.eligible_operational_addresses.write(operational_address, staker_address);
``` [3](#0-2) 

`change_operational_address` validates this consent but does not clear it:

```cairo
assert!(
    self.eligible_operational_addresses.read(operational_address) == staker_address,
    "{}",
    Error::OPERATIONAL_NOT_ELIGIBLE,
);
// ... sets operational_address_to_staker_address, but eligible_operational_addresses is untouched
``` [4](#0-3) 

When the staker later changes to a third operational address, the old one is freed in `operational_address_to_staker_address`:

```cairo
self.operational_address_to_staker_address.write(old_address, Zero::zero());
``` [5](#0-4) 

But `eligible_operational_addresses[old_address]` still equals `staker_address`. Both guards in `change_operational_address` now pass again for the old address, allowing the staker to re-claim it without the operational address re-declaring.

### Impact Explanation
The operational address is the identity used for attestation and reward routing via `get_attestation_info_by_operational_address`. [6](#0-5) 

A staker can forcibly re-associate a previously-used operational address with themselves. The operational address — which may have moved on to serve a different staker — is now locked (`OPERATIONAL_IN_USE` blocks `declare_operational_address` while it is in use) and cannot freely re-declare for another staker. This is **griefing with damage to the operational address operator**: they lose the ability to freely choose which staker they serve, matching the **Medium** impact tier.

### Likelihood Explanation
Any staker who has ever used an operational address and then changed away from it can trigger this. The only prerequisite is that the operational address has not yet called `declare_operational_address(zero)` or `declare_operational_address(other_staker)` to overwrite the stale entry — a race condition the staker can win by acting immediately after the switch.

### Recommendation
Clear the consent entry at the end of `change_operational_address`:

```cairo
self.eligible_operational_addresses.write(operational_address, Zero::zero());
```

This mirrors the fix recommended in the original report: delete the pending/eligible state once it has been consumed.

### Proof of Concept
1. `OP2` calls `declare_operational_address(staker_A)` → `eligible_operational_addresses[OP2] = staker_A`
2. `staker_A` calls `change_operational_address(OP2)` → OP2 is now active; `eligible_operational_addresses[OP2]` is **not cleared**
3. `OP3` calls `declare_operational_address(staker_A)`; `staker_A` calls `change_operational_address(OP3)` → OP2 is freed (`operational_address_to_staker_address[OP2] = 0`), but `eligible_operational_addresses[OP2]` still equals `staker_A`
4. `staker_A` immediately calls `change_operational_address(OP2)` again:
   - `operational_address_to_staker_address[OP2].is_zero()` → **true** ✓
   - `eligible_operational_addresses[OP2] == staker_A` → **true** ✓
   - OP2 is re-associated with `staker_A` without OP2 ever re-declaring consent
5. OP2 is now locked as `staker_A`'s operational address; `declare_operational_address` reverts with `OPERATIONAL_IN_USE`, blocking OP2 from serving any other staker.

### Citations

**File:** src/staking/staking.cairo (L683-703)
```text
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

**File:** src/staking/staking.cairo (L721-722)
```text
            self.eligible_operational_addresses.write(operational_address, staker_address);
            self.emit(Events::OperationalAddressDeclared { operational_address, staker_address });
```

**File:** src/staking/staking.cairo (L1425-1444)
```text
        fn get_attestation_info_by_operational_address(
            self: @ContractState, operational_address: ContractAddress,
        ) -> AttestationInfo {
            let staker_address = self.get_staker_address_by_operational(:operational_address);

            // Return the attestation info.
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            let epoch_info = self.get_epoch_info();
            let epoch_len = epoch_info.epoch_len_in_blocks();
            let epoch_id = epoch_info.current_epoch();
            let current_epoch_starting_block = epoch_info.current_epoch_starting_block();
            let stake = self
                .get_staker_total_strk_balance_at_epoch(
                    :staker_address, :staker_pool_info, :epoch_id,
                )
                .to_strk_native_amount();
            AttestationInfoTrait::new(
                :staker_address, :stake, :epoch_len, :epoch_id, :current_epoch_starting_block,
            )
        }
```

**File:** src/staking/staking.cairo (L1686-1708)
```text
        fn remove_staker(
            ref self: ContractState,
            staker_address: ContractAddress,
            staker_info: InternalStakerInfoLatest,
            staker_pool_info: StoragePath<Mutable<InternalStakerPoolInfoV2>>,
        ) {
            self.insert_staker_own_balance(:staker_address, own_balance: Zero::zero());
            self.staker_info.write(staker_address, VInternalStakerInfo::None);
            let operational_address = staker_info.operational_address;
            self.operational_address_to_staker_address.write(operational_address, Zero::zero());
            staker_pool_info.commission.write(Option::None);
            staker_pool_info.commission_commitment.write(Option::None);
            let pool_contracts = staker_pool_info.get_pools();
            self
                .emit(
                    Events::DeleteStaker {
                        staker_address,
                        reward_address: staker_info.reward_address,
                        operational_address,
                        pool_contracts,
                    },
                );
        }
```
