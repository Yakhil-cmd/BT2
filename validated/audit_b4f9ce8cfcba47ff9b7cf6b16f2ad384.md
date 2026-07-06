Looking at the commission mechanics in `set_commission` / `update_commission` and the delegation entry points to find the analog.### Title
Commission Frontrunning via `set_commission` with Active Commitment — (`src/pool/pool.cairo`, `src/staking/staking.cairo`)

---

### Summary

`enter_delegation_pool` and `switch_delegation_pool` in `pool.cairo` accept no `max_commission` parameter. A staker holding an active `commission_commitment` can call `set_commission` to raise their commission to any value up to `max_commission` in the same block as a delegator's delegation transaction, causing the delegator to receive permanently less yield than they expected.

---

### Finding Description

The Teller Finance M-10 issue is a missing slippage-protection parameter: a privileged party can change a fee between the time a user submits a transaction and the time it executes. The exact same root cause exists here.

**How commission changes work:**

Without a `commission_commitment`, `update_commission` enforces `commission < old_commission` — the staker can only decrease. [1](#0-0) 

However, when an active `commission_commitment` exists, the only constraint is `commission <= max_commission` and `commission != old_commission`. The staker is free to **increase** commission to any value up to `max_commission`: [2](#0-1) 

The protocol's own inline comment acknowledges this: [3](#0-2) 

`set_commission_commitment` allows any staker to set `max_commission` up to `COMMISSION_DENOMINATOR` (10 000 = 100 %): [4](#0-3) 

**The vulnerable entry points:**

`enter_delegation_pool` takes only `reward_address` and `amount` — no `max_commission`: [5](#0-4) 

`switch_delegation_pool` takes only `to_staker`, `to_pool`, and `amount` — no `max_commission`: [6](#0-5) 

Neither function reads or validates the pool's current commission before committing the delegator's funds.

---

### Impact Explanation

A delegator who joins or switches to a pool expecting commission `C` may instead be bound to commission `max_commission` (up to 100 %). All future rewards earned by that delegator are split using the inflated commission rate. Because the commission is applied at reward-distribution time (not at delegation time), every epoch the delegator remains in the pool they lose yield proportional to `(actual_commission − expected_commission)`. This is a direct, ongoing **theft of unclaimed yield** from the delegator.

Impact: **High** — Theft of unclaimed yield.

---

### Likelihood Explanation

The attack requires the staker to have previously called `set_commission_commitment` with a high `max_commission`. This is a permissionless, on-chain action any staker can take at any time. A rational attacker would:

1. Stake and open a pool.
2. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current + epochs_in_year)`.
3. Advertise a low commission (e.g. 1 %) to attract delegators.
4. Monitor the mempool for `enter_delegation_pool` or `switch_delegation_pool` calls targeting their pool.
5. Frontrun with `set_commission(10000)`.

On Starknet, transaction ordering within a block is controlled by the sequencer, so a staker who is also the sequencer (or who bribes the sequencer) can guarantee ordering. Even without sequencer collusion, the staker can submit the `set_commission` call in the same block with a higher fee, making the attack practical.

Likelihood: **Medium** (requires prior setup of a commitment, but that setup is cheap and permissionless).

---

### Recommendation

Add a `max_commission` parameter to both `enter_delegation_pool` and `switch_delegation_pool`. Before transferring funds, assert that the pool's current commission does not exceed the caller-supplied bound:

```rust
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- add
) {
    let current_commission = self.get_commission_from_staking_contract();
    assert!(current_commission <= max_commission, "commission exceeds max");
    // ... rest unchanged
}

fn switch_delegation_pool(
    ref self: ContractState,
    to_staker: ContractAddress,
    to_pool: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- add
) -> Amount {
    // read commission of to_pool from staking contract before switching
    assert!(to_pool_commission <= max_commission, "commission exceeds max");
    // ... rest unchanged
}
```

Alternatively, add a timelock delay between a `set_commission` increase and its effective date (analogous to the Teller recommendation of a timelock on fee changes).

---

### Proof of Concept

```
Block N-1:
  Staker calls set_commission_commitment(max_commission=10000, expiration_epoch=current+100)
  Staker calls set_commission(100)   // advertise 1% commission

Block N (same block, staker tx ordered first):
  Tx 1 (staker):  set_commission(10000)   // raise to 100%
  Tx 2 (delegator): enter_delegation_pool(reward_address, amount)
                    // no max_commission check → delegator locked into 100%

All subsequent epochs:
  Delegator earns rewards, but 100% is taken as commission.
  Delegator receives 0 yield despite expecting 1%.
```

The delegator's `pool_member_info_v1` will show `commission: 10000` after the switch, confirming the inflated rate is applied to all future reward distributions via `get_commission_from_staking_contract`: [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L748-778)
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

**File:** src/pool/pool.cairo (L182-184)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
```

**File:** src/pool/pool.cairo (L379-384)
```text
        fn switch_delegation_pool(
            ref self: ContractState,
            to_staker: ContractAddress,
            to_pool: ContractAddress,
            amount: Amount,
        ) -> Amount {
```

**File:** src/pool/pool.cairo (L935-948)
```text
        fn get_commission_from_staking_contract(self: @ContractState) -> Commission {
            if self.staker_removed.read() {
                return Zero::zero();
            }
            let staking_dispatcher = IStakingDispatcher {
                contract_address: self.staking_pool_dispatcher.contract_address.read(),
            };
            // The staker must have commission since it has a pool (this contract). So unwrap is
            // safe.
            staking_dispatcher
                .staker_pool_info(staker_address: self.staker_address.read())
                .commission
                .unwrap()
        }
```
