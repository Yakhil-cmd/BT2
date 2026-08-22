## Title
Integer-division truncation in `minimum_stake()` can zero out the `InsufficientStake` protection, letting a `Stake` action bypass minimum staking requirement - (File: `chain/epoch-manager/src/lib.rs`)

### Summary
The reported bug class is: a "minimum required amount" is computed as `X / DIVISOR`, and when `X` is small (e.g. right after deployment/restart when the pool is empty), integer division truncates the result to `0`, silently disabling the minimum-amount check and letting a caller satisfy the requirement with a negligible or zero value. The same pattern exists in nearcore's staking-validation logic: `EpochManager::minimum_stake()` computes the minimum allowed stake as `seat_price / minimum_stake_divisor`, and this result is used directly to gate the `InsufficientStake` check in `action_stake`.

### Finding Description
`EpochManager::minimum_stake` derives the protocol's minimum stake threshold from the previous epoch's `seat_price` divided by the genesis/epoch-config parameter `minimum_stake_divisor` (default `10`): [1](#0-0) 

This value is consumed directly, without any lower bound, inside the `Stake` action handler: [2](#0-1) 

If `seat_price` (the per-seat stake threshold computed by `find_threshold`) is smaller than `minimum_stake_divisor`, the integer division `seat_price.checked_div(stake_divisor)` truncates to `0`. In that case, `stake.stake < minimum_stake` (i.e. `stake.stake < 0`) can never be true for any positive `stake.stake`, so the `InsufficientStake` guard is effectively disabled — any unprivileged account can submit a `Stake` transaction with a value as small as `1` yoctoNEAR and have it accepted as a valid validator proposal, exactly mirroring the reported pattern where `_minimumYeetPoint()` truncates to `0` when `totalPot` is small, letting a caller satisfy `msg.value >= minimumYeetPoint` with `0` wei.

`seat_price` itself is derived via `find_threshold`, whose only invariant is that the total stake must be at least `num_seats` yoctoNEAR — i.e., `seat_price` can be as low as `1` yoctoNEAR in a low-stake network (e.g. a small/private chain or non-production genesis configuration): [3](#0-2) 

The documentation explicitly states the intended design contract that this bug violates — "the minimum stake is determined by `last_epoch_seat_price / minimum_stake_divisor`" — with no fallback for when this division underflows to zero: [4](#0-3) 

### Impact Explanation
When `minimum_stake()` truncates to `0`, the `InsufficientStake` validation in `action_stake` becomes a no-op, so an unprivileged account can submit a `Stake` transaction (fully reachable from RPC) with a stake far below the intended economic threshold and have it registered as a valid `ValidatorStake` proposal: [5](#0-4) 

This weakens the protocol's intended minimum economic bar for participating in validator elections. The final validator/chunk-producer selection is still additionally gated by the separate `min_stake_ratio` check in `select_validators`, which limits the practical severity — bypassing `minimum_stake` alone does not automatically make an attacker an elected validator. However, it still represents a broken security invariant (an unauthorized state change: a proposal that should have been rejected per protocol economics is instead accepted) and is directly analogous to the reported bug class of a division-based minimum threshold silently collapsing to zero. [6](#0-5) 

### Likelihood Explanation
Exploitability depends on `seat_price` being small relative to `minimum_stake_divisor` (default `10`), which requires either: a genesis/testnet/private-chain configuration with very low total stake (bounded only by `num_seats` yoctoNEAR per `find_threshold`), or specific low-stake epochs. On mainnet/testnet-scale networks with large total stake, `seat_price` is large enough that this truncation is not observed in practice, which lowers overall likelihood, but the underlying arithmetic bug is present unconditionally in the code path.

### Recommendation
In `EpochManager::minimum_stake` (`chain/epoch-manager/src/lib.rs`), avoid unguarded integer division that can silently degrade the security check to zero: enforce a protocol-defined absolute floor for the minimum stake (e.g. `max(seat_price / minimum_stake_divisor, MIN_ABSOLUTE_STAKE)`), or use rounding-up (ceiling) division so that any nonzero `seat_price` yields a nonzero minimum stake, consistent with the recommendation in the original report to require a floor amount rather than relying purely on division.

### Proof of Concept
1. Configure (or observe) an epoch where `seat_price < minimum_stake_divisor` (e.g. a low-stake genesis/private chain where `find_threshold` returns a `seat_price` of `1`–`9` yoctoNEAR while `minimum_stake_divisor = 10`).
2. Call `EpochManager::minimum_stake(prev_block_hash)`; observe it returns `Balance::from_yoctonear(0)` due to `seat_price.checked_div(10)` truncation (`chain/epoch-manager/src/lib.rs:1675`).
3. Submit a `Stake` transaction with `stake.stake = 1` yoctoNEAR.
4. In `action_stake` (`runtime/runtime/src/actions.rs:62-73`), the check `stake.stake < minimum_stake` evaluates `1 < 0`, which is `false`, so no `InsufficientStake` error is raised and the proposal is pushed into `result.validator_proposals`, despite being far below the intended economic minimum for staking.

### Citations

**File:** chain/epoch-manager/src/lib.rs (L1665-1676)
```rust
    /// Get minimum stake allowed at current block. Attempts to stake with a lower stake will be
    /// rejected.
    pub fn minimum_stake(&self, prev_block_hash: &CryptoHash) -> Result<Balance, EpochError> {
        let next_epoch_id = self.get_next_epoch_id_from_prev_block(prev_block_hash)?;
        let (protocol_version, seat_price) = {
            let epoch_info = self.get_epoch_info(&next_epoch_id)?;
            (epoch_info.protocol_version(), epoch_info.seat_price())
        };
        let config = self.config.for_protocol_version(protocol_version);
        let stake_divisor = { config.minimum_stake_divisor };
        Ok(seat_price.checked_div(u128::from(stake_divisor)).unwrap())
    }
```

**File:** runtime/runtime/src/actions.rs (L62-73)
```rust
        if stake.stake > Balance::ZERO {
            let minimum_stake = epoch_info_provider.minimum_stake(last_block_hash)?;
            if stake.stake < minimum_stake {
                result.result = Err(ActionErrorKind::InsufficientStake {
                    account_id: account_id.clone(),
                    stake: stake.stake,
                    minimum_stake,
                }
                .into());
                return Ok(());
            }
        }
```

**File:** runtime/runtime/src/actions.rs (L75-84)
```rust
        result.validator_proposals.push(ValidatorStake::new(
            account_id.clone(),
            stake.public_key.clone(),
            stake.stake,
        ));
        if stake.stake > account.locked() {
            // We've checked above `account.amount >= increment`
            account.set_amount(new_balance);
            account.set_locked(stake.stake);
        }
```

**File:** chain/epoch-manager/src/genesis.rs (L166-195)
```rust
pub(crate) fn find_threshold(
    stakes: &[Balance],
    num_seats: NumSeats,
) -> Result<Balance, EpochError> {
    let stake_sum: Balance =
        stakes.iter().fold(Balance::ZERO, |sum, item| sum.checked_add(*item).unwrap());
    let min_possible_stake = Balance::from_yoctonear(u128::from(num_seats));
    if stake_sum < min_possible_stake {
        return Err(EpochError::ThresholdError { stake_sum, num_seats });
    }
    let (mut left, mut right): (Balance, Balance) =
        (Balance::from_yoctonear(1), stake_sum.checked_add(Balance::from_yoctonear(1)).unwrap());
    'outer: loop {
        if left == right.checked_sub(Balance::from_yoctonear(1)).unwrap() {
            break Ok(left);
        }
        let mid = left.checked_add(right).unwrap().checked_div(2).unwrap();
        let mut current_sum = Balance::ZERO;
        for item in stakes {
            current_sum =
                current_sum.checked_add(item.checked_div(mid.as_yoctonear()).unwrap()).unwrap();
            let min_possible_stake = Balance::from_yoctonear(u128::from(num_seats));
            if current_sum >= min_possible_stake {
                left = mid;
                continue 'outer;
            }
        }
        right = mid;
    }
}
```

**File:** docs/RuntimeSpec/Actions.md (L186-198)
```markdown
- If the staked amount is below the minimum stake threshold, the following error will be returned:

```rust
InsufficientStake {
    account_id: AccountId,
    stake: Balance,
    minimum_stake: Balance,
}
```

The minimum stake is determined by `last_epoch_seat_price / minimum_stake_divisor` where `last_epoch_seat_price` is the
seat price determined at the end of last epoch and `minimum_stake_divisor` is a genesis config parameter and its current
value is 10.
```

**File:** chain/epoch-manager/src/validator_selection.rs (L357-396)
```rust
fn select_validators(
    mut proposals: BinaryHeap<OrderedValidatorStake>,
    max_number_selected: usize,
    min_stake_ratio: Ratio<u128>,
) -> (Vec<ValidatorStake>, BinaryHeap<OrderedValidatorStake>, Balance) {
    let mut total_stake = Balance::ZERO;
    let n = cmp::min(max_number_selected, proposals.len());
    let mut validators = Vec::with_capacity(n);
    for _ in 0..n {
        let p = proposals.pop().unwrap().0;
        let p_stake = p.stake();
        let total_stake_with_p = total_stake.checked_add(p_stake).unwrap();
        if total_stake_with_p > Balance::ZERO
            && Ratio::new(p_stake.as_yoctonear(), total_stake_with_p.as_yoctonear())
                > min_stake_ratio
        {
            validators.push(p);
            total_stake = total_stake_with_p;
        } else {
            // p was not included, return it to the list of proposals
            proposals.push(OrderedValidatorStake(p));
            break;
        }
    }
    let threshold = if validators.len() == max_number_selected {
        // all slots were filled, so the threshold stake is 1 more than the current
        // smallest stake
        validators.last().unwrap().stake().checked_add(Balance::from_yoctonear(1)).unwrap()
    } else {
        // the stake ratio condition prevented all slots from being filled,
        // or there were fewer proposals than available slots,
        // so the threshold stake is whatever amount pass the stake ratio condition
        Balance::from_yoctonear(
            (min_stake_ratio * Ratio::from_integer(total_stake.as_yoctonear())
                / (Ratio::from_integer(1u128) - min_stake_ratio))
                .ceil()
                .to_integer(),
        )
    };
    (validators, proposals, threshold)
```
