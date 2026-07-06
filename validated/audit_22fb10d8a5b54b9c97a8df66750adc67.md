### Title
Commission Can Be Increased to 100% After Delegators Have Delegated, Stealing Their Yield - (File: src/staking/staking.cairo)

### Summary
A staker can call `set_commission_commitment` with `max_commission = 10000` (100%) and then immediately call `set_commission(10000)` to raise commission from 0% to 100% after delegators have already delegated. Because commission is applied at attestation/reward-distribution time using the **current** commission value, all delegator rewards for the commitment period are redirected to the staker. Delegators cannot exit immediately due to the mandatory exit window, and the attack can be repeated after each commitment expires.

### Finding Description
The protocol enforces that without an active commitment, commission can only decrease: [1](#0-0) 

However, `set_commission_commitment` allows a staker to set a `max_commission` that is **higher** than the current commission, with no restriction on how large the jump can be: [2](#0-1) 

Once the commitment is active, `update_commission` permits raising commission to any value up to `max_commission`: [3](#0-2) 

The code itself acknowledges this gap: [4](#0-3) 

At reward-distribution time, `calculate_staker_pools_rewards` reads the **current** commission from storage and applies it to split rewards between the staker and the pool: [5](#0-4) 

The split function: [6](#0-5) 

There is no snapshot of the commission at delegation time. The commission used is whatever is stored at the moment the staker attests.

**Attack sequence:**
1. Staker opens a pool with `commission = 0` to attract delegators.
2. Delegators call `enter_delegation_pool` / `add_to_delegation_pool`.
3. Staker calls `set_commission_commitment(max_commission=10000, expiration_epoch=current_epoch+N)` — valid because `0 <= 10000`.
4. Staker immediately calls `set_commission(commission=10000)`.
5. On the next attestation, `calculate_staker_pools_rewards` uses `commission = 10000`, so `pool_rewards = 0` and all rewards go to the staker.
6. Delegators are trapped in the exit window and continue earning 0 net rewards until they can exit.
7. After the commitment expires, the staker decreases commission, attracts new delegators, and repeats.

### Impact Explanation
This is **theft of unclaimed yield**. Delegators who delegated expecting 0% commission receive 0 STRK rewards for the entire commitment period (up to one year). The staker captures 100% of the pool's reward share as commission. The delegators' principal is not at risk, but all accrued yield is stolen.

### Likelihood Explanation
Any staker with an active pool can execute this in two transactions with no special privileges. There is a clear profit motive (more commission). The only cost is reputational, but a staker can create a fresh address for each attack cycle. The exit window (which can be days or weeks) ensures delegators cannot escape before at least one reward epoch is stolen.

### Recommendation
1. **Enforce a delay** between setting a commitment and being allowed to increase commission (e.g., the increase only takes effect `K` epochs after the commitment is set), giving delegators time to exit.
2. **Alternatively**, snapshot the commission at delegation time and use the snapshotted value for reward calculation for each delegator, analogous to the fix in the referenced report (storing the fee in the meta batch).
3. **At minimum**, require that `set_commission_commitment` can only be called before any delegators have entered the pool, so the max commission is known upfront.

### Proof of Concept
```
// Epoch E: Staker stakes with commission=0, pool opens.
staking.stake(reward_addr, op_addr, amount);
staking.set_commission(commission: 0);
staking.set_open_for_delegation(token_address: STRK);

// Epoch E: Delegator delegates expecting 0% commission.
pool.enter_delegation_pool(reward_addr, amount);

// Epoch E (same block or next): Staker sets commitment and raises commission.
staking.set_commission_commitment(max_commission: 10000, expiration_epoch: E + 1);
staking.set_commission(commission: 10000);

// Epoch E+1: Staker attests.
// calculate_staker_pools_rewards reads commission=10000.
// split_rewards_with_commission → pool_rewards = 0, commission_rewards = total.
// Delegator receives 0 STRK from pool.claim_rewards().
attestation.attest(block_hash);
pool.claim_rewards(delegator); // returns 0
```

### Citations

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L748-785)
```text
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

**File:** src/staking/staking.cairo (L1580-1597)
```text
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
```

**File:** src/staking/staking.cairo (L1964-1991)
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
```

**File:** src/staking/utils.cairo (L68-76)
```text
pub(crate) fn split_rewards_with_commission(
    rewards_including_commission: Amount, commission: Commission,
) -> (Amount, Amount) {
    let commission_rewards = compute_commission_amount_rounded_down(
        :rewards_including_commission, :commission,
    );
    let pool_rewards = rewards_including_commission - commission_rewards;
    (commission_rewards, pool_rewards)
}
```
