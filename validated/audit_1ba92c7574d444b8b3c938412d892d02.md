### Title
Staker Can Atomically Set Commission Commitment Then Immediately Raise Commission to 100%, Stealing Delegator Yield - (File: `src/staking/staking.cairo`)

### Summary
The `set_commission_commitment` + `set_commission` two-step sequence is the direct analog of H-02's threshold-lower + controller-remove attack. A staker can call both functions in the same block: first setting a commitment with `max_commission = 10000` (100%), then immediately calling `set_commission(10000)`. This bypasses the normal "commission can only decrease" invariant with zero delay, stealing delegators' unclaimed yield for the current epoch before they can exit.

### Finding Description

Without a commitment, `update_commission` enforces a strict decrease:

```rust
} else {
    assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
}
```

With an active commitment, the guard is replaced by:

```rust
if self.is_commission_commitment_active(:commission_commitment) {
    assert!(
        commission <= commission_commitment.max_commission,
        "{}",
        Error::INVALID_COMMISSION_WITH_COMMITMENT,
    );
    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
}
``` [1](#0-0) 

`set_commission_commitment` only requires `max_commission >= current_commission`:

```rust
let current_commission = staker_pool_info.commission();
assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
``` [2](#0-1) 

So a staker with `commission = 200` can:

1. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)` — this is the "threshold lowering" step; it replaces the strict-decrease guard with `commission <= 10000`.
2. Immediately call `set_commission(commission: 10000)` — this is the "exploit" step; commission jumps from 2% to 100% in the same block.

The commission is written to storage immediately with no epoch delay:

```rust
staker_pool_info.commission.write(Option::Some(commission));
``` [3](#0-2) 

The developers themselves noted this gap:

```rust
/// **Note**: Current commission increase safeguards still allow for sudden commission
/// changes.
fn set_commission_commitment(...)
``` [4](#0-3) 

### Impact Explanation

Rewards are calculated per epoch when `update_rewards_from_attestation_contract` is called. The commission stored at that moment determines the staker/delegator split. If the staker raises commission to 100% before that call fires in the current epoch, the entire epoch's reward allocation goes to the staker and zero to delegators. Delegators' stake was active and earning yield during the epoch; that yield is redirected to the staker. This is **theft of unclaimed yield** (High impact). [5](#0-4) [6](#0-5) 

### Likelihood Explanation

**Medium.** Any staker who has opened a delegation pool can execute this in two back-to-back transactions (or a single multicall). No privileged role is required beyond being a registered staker. The staker sacrifices future delegations but profits from the current epoch's pooled rewards. The attack is more attractive the larger the delegated pool.

### Recommendation

Introduce a minimum delay between setting a commitment and being able to raise commission under it. For example, require that `expiration_epoch - current_epoch >= K` before the commitment becomes active for upward changes, giving delegators at least one full K-epoch window to observe the commitment and exit. Alternatively, disallow commission increases entirely and restrict the commitment to only allow decreases within the committed range.

### Proof of Concept

```
// Setup: staker has commission = 200 (2%), pool has delegators with accrued yield
// Block N:
staking.set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1);
staking.set_commission(commission: 10000);  // same block, commission now 100%

// Block N+1 (same epoch): attestation fires
attestation.attest();
// → update_rewards_from_attestation_contract called
// → split_rewards_with_commission uses commission = 10000
// → 100% of epoch rewards go to staker, 0% to delegators
// Delegators' unclaimed yield for this epoch is stolen.
``` [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L725-743)
```text
        fn set_commission(ref self: ContractState, commission: Commission) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            if let Option::Some(old_commission) = staker_pool_info.commission.read() {
                self
                    .update_commission(
                        :staker_address, :staker_pool_info, :old_commission, :commission,
                    );
            } else {
                staker_pool_info.commission.write(Option::Some(commission));
                self.emit(Events::CommissionInitialized { staker_address, commission });
            }
        }
```

**File:** src/staking/staking.cairo (L745-785)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
        fn set_commission_commitment(
            ref self: ContractState, max_commission: Commission, expiration_epoch: Epoch,
        ) {
            self.general_prerequisites();
            assert!(max_commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            assert!(staker_pool_info.has_pool(), "{}", Error::MISSING_POOL_CONTRACT);
            let current_epoch = self.get_current_epoch();
            if let Option::Some(commission_commitment) = staker_pool_info
                .commission_commitment
                .read() {
                assert!(
                    !self.is_commission_commitment_active(:commission_commitment),
                    "{}",
                    Error::COMMISSION_COMMITMENT_EXISTS,
                );
            }
            // Staker must have a commission since it has a pool.
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
            assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
            assert!(
                expiration_epoch - current_epoch <= self.get_epoch_info().epochs_in_year(),
                "{}",
                Error::EXPIRATION_EPOCH_TOO_FAR,
            );
            let commission_commitment = CommissionCommitment { max_commission, expiration_epoch };
            staker_pool_info.commission_commitment.write(Option::Some(commission_commitment));
            self
                .emit(
                    Events::CommissionCommitmentSet {
                        staker_address, max_commission, expiration_epoch,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L1573-1609)
```text
        fn update_commission(
            ref self: ContractState,
            staker_address: ContractAddress,
            staker_pool_info: StoragePath<Mutable<InternalStakerPoolInfoV2>>,
            old_commission: Commission,
            commission: Commission,
        ) {
            if let Option::Some(commission_commitment) = staker_pool_info
                .commission_commitment
                .read() {
                if self.is_commission_commitment_active(:commission_commitment) {
                    assert!(
                        commission <= commission_commitment.max_commission,
                        "{}",
                        Error::INVALID_COMMISSION_WITH_COMMITMENT,
                    );
                    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
                } else {
                    assert!(
                        commission < old_commission, "{}", Error::COMMISSION_COMMITMENT_EXPIRED,
                    );
                }
            } else {
                assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
            }

            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));

            // Emit event.
            self
                .emit(
                    Events::CommissionChanged {
                        staker_address, old_commission, new_commission: commission,
                    },
                );
        }
```
