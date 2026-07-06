### Title
Commission Commitment Expires One Epoch Early Due to Strict `<` Comparison - (File: src/staking/staking.cairo)

### Summary

The `is_commission_commitment_active` function in `src/staking/staking.cairo` uses a strict `<` comparison instead of `<=`, causing a commission commitment to be treated as expired at the `expiration_epoch` itself rather than after it. This allows a staker to bypass the commission commitment protection one epoch earlier than delegators expect, enabling an immediate commission increase at `expiration_epoch` by first setting a new commitment with a higher `max_commission`.

### Finding Description

The `is_commission_commitment_active` helper function determines whether a staker's commission commitment is still binding:

```cairo
fn is_commission_commitment_active(
    self: @ContractState, commission_commitment: CommissionCommitment,
) -> bool {
    self.get_current_epoch() < commission_commitment.expiration_epoch
}
``` [1](#0-0) 

When `current_epoch == expiration_epoch`, this returns `false`, treating the commitment as already expired. This result is consumed in two places:

**1. `set_commission_commitment`** — allows setting a new commitment only when the old one is inactive:

```cairo
assert!(
    !self.is_commission_commitment_active(:commission_commitment),
    "{}",
    Error::COMMISSION_COMMITMENT_EXISTS,
);
``` [2](#0-1) 

**2. `update_commission`** — enforces the max_commission cap only while the commitment is active:

```cairo
if self.is_commission_commitment_active(:commission_commitment) {
    assert!(
        commission <= commission_commitment.max_commission, ...
    );
} else {
    assert!(commission < old_commission, "{}", Error::COMMISSION_COMMITMENT_EXPIRED);
}
``` [3](#0-2) 

**Attack sequence at `current_epoch == expiration_epoch`:**

1. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: expiration_epoch + 1)`. Because `is_commission_commitment_active(old_commitment)` returns `false`, the `COMMISSION_COMMITMENT_EXISTS` guard passes and the new commitment is written.
2. Staker immediately calls `set_commission(commission: 10000)`. The new commitment is now active (`current_epoch < expiration_epoch + 1`), so `commission <= max_commission` (10000 ≤ 10000) passes and commission is raised to the maximum.

Delegators who joined under the original commitment expected it to remain binding through `expiration_epoch`, but the staker can raise commission to any value at that epoch.

### Impact Explanation

Delegators' unclaimed yield is reduced by the unexpected commission increase. The staker captures the difference between the committed `max_commission` and the new (higher) commission for every reward distribution that occurs at or after `expiration_epoch` in the same epoch. This constitutes theft of unclaimed yield from delegators.

### Likelihood Explanation

The `expiration_epoch` is a public, on-chain value. A rational staker who wants to maximize commission can trivially observe when their commitment expires and execute the two-step bypass atomically at the start of `expiration_epoch`. No privileged access, leaked keys, or external dependencies are required — only the staker's own operational address.

### Recommendation

Change the comparison in `is_commission_commitment_active` from strict `<` to `<=`:

```cairo
fn is_commission_commitment_active(
    self: @ContractState, commission_commitment: CommissionCommitment,
) -> bool {
    self.get_current_epoch() <= commission_commitment.expiration_epoch
}
```

This ensures the commitment remains binding during `expiration_epoch` itself, consistent with delegators' reasonable expectation that a commitment with `expiration_epoch = E` protects them through epoch `E`.

### Proof of Concept

```
// Setup: staker has commission = 500, sets commitment {max_commission: 1000, expiration_epoch: E}
// Delegators join expecting commission ≤ 1000 through epoch E.

// At epoch E:
// Step 1 — old commitment is treated as expired (E < E is false)
staker.set_commission_commitment(max_commission: 10000, expiration_epoch: E + 1);
// Step 2 — new commitment is active (E < E+1 is true), cap is now 10000
staker.set_commission(commission: 10000);
// Commission is now 10000, one epoch before delegators expected protection to end.
// All rewards distributed at epoch E are split with 10000/10000 commission to staker.
```

### Citations

**File:** src/staking/staking.cairo (L762-766)
```text
                assert!(
                    !self.is_commission_commitment_active(:commission_commitment),
                    "{}",
                    Error::COMMISSION_COMMITMENT_EXISTS,
                );
```

**File:** src/staking/staking.cairo (L1583-1594)
```text
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
```

**File:** src/staking/staking.cairo (L2178-2182)
```text
        fn is_commission_commitment_active(
            self: @ContractState, commission_commitment: CommissionCommitment,
        ) -> bool {
            self.get_current_epoch() < commission_commitment.expiration_epoch
        }
```
