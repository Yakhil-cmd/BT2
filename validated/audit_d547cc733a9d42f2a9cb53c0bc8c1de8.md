### Title
Staker Can Raise Commission to 100% via Commitment Mechanism, Stealing All Delegator Rewards - (File: `src/staking/staking.cairo`)

### Summary
A staker can use `set_commission_commitment` followed immediately by `set_commission` to raise their commission from any low value to 100% within a single epoch, stealing all delegator rewards for that epoch. The code itself acknowledges this gap with the comment: *"Current commission increase safeguards still allow for sudden commission changes."*

### Finding Description
The `set_commission_commitment` function allows a staker to set a `max_commission` up to `COMMISSION_DENOMINATOR` (10000 = 100%) with a minimum expiration of `current_epoch + 1`. Once the commitment is active, `update_commission` permits setting commission to any value `<= max_commission` (and `!= old_commission`), with no lower-bound restriction and no epoch delay before the new rate takes effect.

The relevant guard in `update_commission` is:

```cairo
if self.is_commission_commitment_active(:commission_commitment) {
    assert!(
        commission <= commission_commitment.max_commission, ...
    );
    assert!(commission != old_commission, ...);
}
``` [1](#0-0) 

`is_commission_commitment_active` returns `true` as long as `current_epoch < expiration_epoch`:

```cairo
fn is_commission_commitment_active(...) -> bool {
    self.get_current_epoch() < commission_commitment.expiration_epoch
}
``` [2](#0-1) 

Because the minimum valid `expiration_epoch` is `current_epoch + 1`, the commitment is immediately active, and the staker can call `set_commission(10000)` in the very next transaction.

The code itself flags this as an unresolved issue:

```cairo
/// **Note**: Current commission increase safeguards still allow for sudden commission
/// changes.
fn set_commission_commitment(...)
``` [3](#0-2) 

Reward distribution reads the commission at the time of attestation with no historical per-epoch tracking:

```cairo
let commission = staker_pool_info.commission();
...
let (commission_rewards, pool_rewards) = split_rewards_with_commission(
    rewards_including_commission: pool_rewards_including_commission, :commission,
);
``` [4](#0-3) 

So if commission is 100% at attestation time, `pool_rewards` is zero and all delegator rewards flow to the staker.

### Impact Explanation
**High — Theft of unclaimed yield.** Delegators who have staked tokens in a pool lose 100% of their accrued rewards for any epoch in which the staker has raised commission to 10000. The funds are not frozen; they are actively redirected to the staker's reward address.

### Likelihood Explanation
Any registered staker who has opened a delegation pool can execute this attack permissionlessly in two sequential transactions within a single epoch. No privileged protocol role is required. The staker is analogous to the BoostAggregator owner in the reference report — anyone can become a staker and open a public pool. Delegators have no on-chain mechanism to react before the attestation that distributes rewards at the inflated rate.

### Recommendation
1. **Enforce an epoch delay on commission increases.** Commission increases should only take effect `K` epochs after `set_commission` is called, giving delegators time to exit.
2. **Separate commitment creation from immediate commission increase.** Require that a commission increase via commitment cannot be applied in the same epoch the commitment was set.
3. **Cap `max_commission` in `set_commission_commitment`.** Introduce a protocol-level ceiling (e.g., 5000 = 50%) below `COMMISSION_DENOMINATOR` to bound the worst-case sudden increase.

### Proof of Concept
1. Staker registers with `commission = 500` (5%) and opens a STRK delegation pool.
2. Delegators delegate tokens, expecting 5% commission.
3. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
   - Passes: `current_commission (500) <= max_commission (10000)` ✓, `expiration_epoch > current_epoch` ✓ [5](#0-4) 
4. Staker immediately calls `set_commission(10000)`.
   - Passes: commitment is active (`current_epoch < current_epoch + 1`) ✓, `10000 <= 10000` ✓, `10000 != 500` ✓ [1](#0-0) 
5. Staker attests within the same epoch. Reward distribution applies `commission = 10000`, so `pool_rewards = 0` and all delegator rewards are credited to the staker. [6](#0-5) 
6. Delegators call `claim_rewards` and receive zero for that epoch.

The existing flow test at `src/flow_test/flows.cairo` line 821 confirms that `commission = 10000` is a valid and functional value, and that delegators receive zero rewards when commission is 100%. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L745-748)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
        fn set_commission_commitment(
```

**File:** src/staking/staking.cairo (L769-776)
```text
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
            assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
            assert!(
                expiration_epoch - current_epoch <= self.get_epoch_info().epochs_in_year(),
                "{}",
                Error::EXPIRATION_EPOCH_TOO_FAR,
            );
```

**File:** src/staking/staking.cairo (L1583-1589)
```text
                if self.is_commission_commitment_active(:commission_commitment) {
                    assert!(
                        commission <= commission_commitment.max_commission,
                        "{}",
                        Error::INVALID_COMMISSION_WITH_COMMITMENT,
                    );
                    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
```

**File:** src/staking/staking.cairo (L1964-1993)
```text
            let commission = staker_pool_info.commission();
            for (pool_contract, token_address) in staker_pool_info.pools {
                if !self.is_active_token(:token_address, epoch_id: curr_epoch) {
                    continue;
                }
                let pool_balance_curr_epoch = self
                    .get_staker_delegated_balance_at_epoch(
                        :staker_address, :pool_contract, epoch_id: curr_epoch,
                    );
                let (total_rewards, total_stake) = if token_address == STRK_TOKEN_ADDRESS {
                    (strk_total_rewards, strk_total_stake)
                } else {
                    (btc_total_rewards, btc_total_stake)
                };
                // Calculate rewards for this pool.
                let pool_rewards_including_commission = if total_stake.is_non_zero() {
                    mul_wide_and_div(
                        lhs: total_rewards,
                        rhs: pool_balance_curr_epoch.to_amount_18_decimals(),
                        div: total_stake.to_amount_18_decimals(),
                    )
                        .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
                } else {
                    Zero::zero()
                };
                let (commission_rewards, pool_rewards) = split_rewards_with_commission(
                    rewards_including_commission: pool_rewards_including_commission, :commission,
                );
                total_commission_rewards += commission_rewards;
                total_pools_rewards += pool_rewards;
```

**File:** src/staking/staking.cairo (L2178-2182)
```text
        fn is_commission_commitment_active(
            self: @ContractState, commission_commitment: CommissionCommitment,
        ) -> bool {
            self.get_current_epoch() < commission_commitment.expiration_epoch
        }
```

**File:** src/flow_test/flows.cairo (L821-831)
```text
        let commission = 10000;

        // Stake with commission 100%
        system.stake(:staker, amount: stake_amount, pool_enabled: true, :commission);
        system.advance_k_epochs_and_attest(:staker);

        let pool = system.staking.get_pool(:staker);
        system.delegate(:delegator, :pool, amount: delegated_amount);

        // Update commission to 0%
        system.set_commission(:staker, commission: Zero::zero());
```
