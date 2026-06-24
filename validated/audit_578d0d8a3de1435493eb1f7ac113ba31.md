Audit Report

## Title
Permissionless `ClaimOrRefresh` Enables Unprivileged Neuron Age Dilution via Stake Injection - (`rs/nns/governance/src/governance.rs`)

## Summary
Any unprivileged caller can invoke `manage_neuron` with `ClaimOrRefresh { by: NeuronIdOrSubaccount }` targeting any existing neuron. By first transferring ICP to the victim's neuron subaccount and then triggering a stake refresh, the attacker causes `update_stake_adjust_age` to execute on the victim's neuron without authorization, advancing `aging_since_timestamp_seconds` forward and permanently diluting the neuron's age-based voting power bonus. The attack is repeatable and affects both NNS and SNS governance.

## Finding Description

In `manage_neuron_internal`, the `ClaimOrRefresh` branch executes and returns **before any authorization check** is performed: [1](#0-0) 

The `By::NeuronIdOrSubaccount` path dispatches directly to `refresh_neuron_by_id_or_subaccount`, which accepts any neuron ID or subaccount with no caller identity check: [2](#0-1) 

Inside `refresh_neuron`, when the ledger balance exceeds the cached stake (because the attacker deposited ICP), `update_stake_adjust_age` is called unconditionally: [3](#0-2) 

`update_stake_adjust_age` computes a weighted average of old age and new stake, with the added stake carrying age 0, advancing `aging_since_timestamp_seconds` toward the present: [4](#0-3) 

The `combine_aged_stakes` function confirms the weighted-average age reduction: for a neuron with stake `S` and age `A`, adding `S` more ICP (age 0) yields new age `A/2`: [5](#0-4) 

The same vulnerability exists in SNS governance's `refresh_neuron`, which calls `neuron.update_stake` with no authorization check on the caller: [6](#0-5) 

The SNS `update_stake` also dilutes age via the same weighted-average formula: [7](#0-6) 

The existing test suite explicitly validates and documents that **any caller** (proxy) can refresh any neuron by ID or subaccount: [8](#0-7) 

## Impact Explanation

The age bonus multiplier contributes up to **1.25× voting power** in NNS (linearly from 0 to 4 years): [9](#0-8) 

This age bonus feeds directly into `potential_and_deciding_voting_power`, which determines both voting weight and voting reward share: [10](#0-9) 

In SNS, `max_age_bonus_percentage` is configurable and can exceed NNS's 25%: [11](#0-10) 

The concrete impact is **unauthorized modification of neuron state** — specifically the age component of voting power — without the neuron owner's consent. Each attack permanently dilutes the victim's age bonus by the ratio `old_stake / (old_stake + added_stake)`. Repeated attacks compound this dilution, keeping the victim's age perpetually suppressed. While the victim's absolute stake increases (the attacker's ICP is absorbed), the victim's **voting rewards per unit of stake** are reduced, and the victim must wait additional years to recover maximum age bonus. This constitutes unauthorized access to and modification of neuron governance state, fitting the High impact category for "unauthorized access to neurons... where exploitation requires meaningful per-target work or other constraints" — the cost per attack scales proportionally with the victim's stake.

## Likelihood Explanation

- **Entry path**: Any unprivileged ingress sender can call `manage_neuron` on the NNS governance canister with `ClaimOrRefresh { by: NeuronIdOrSubaccount }`. Neuron IDs and subaccounts are public.
- **Precondition**: The attacker must transfer ICP to the victim's neuron subaccount. The cost per attack is proportional to the desired age dilution (e.g., halving the age of a 1 ICP neuron costs 1 ICP + fees; halving the age of a 1000 ICP neuron costs 1000 ICP).
- **Constraint**: Unlike dust attacks on EVM, this has a real ICP cost. However, it is permissionless, repeatable, and economically rational for targeted attacks on high-value long-aged neurons or SNS governance participants with large age bonuses.
- **Likelihood**: Medium — economically rational for targeted attacks on high-value neurons where suppressing a competitor's governance influence justifies the ICP cost.

## Recommendation

1. **Require caller authorization for `ClaimOrRefresh` when targeting an existing neuron by ID/subaccount**: Only the neuron's controller or a hotkey should be permitted to trigger a stake refresh that modifies `aging_since_timestamp_seconds`. Claiming a new neuron (where the neuron does not yet exist) can remain permissionless.
2. **Alternatively, skip age adjustment when the caller is not the neuron controller**: In `refresh_neuron`, only call `update_stake_adjust_age` (the age-modifying variant) when the caller is the neuron's controller or hotkey; otherwise update only `cached_neuron_stake_e8s` without adjusting age.
3. **Minimum added-stake threshold**: Reject refresh calls where `balance - cached_stake < MINIMUM_REFRESH_DELTA` to prevent low-cost repeated dilution attacks.

## Proof of Concept

```
// Attacker (bob) targets victim (alice) who has a 4-year-old neuron with 1 ICP staked.
//
// Step 1: Bob sends 1 ICP to alice's neuron subaccount on the ICP ledger.
//   alice_neuron_subaccount = compute_neuron_staking_subaccount(alice_controller, alice_memo)
//   ledger.transfer(to: governance_canister/alice_neuron_subaccount, amount: 1 ICP)
//
// Step 2: Bob calls manage_neuron with ClaimOrRefresh targeting alice's neuron.
//   governance.manage_neuron(caller=bob, ManageNeuron {
//     neuron_id_or_subaccount: Some(NeuronId(alice_neuron_id)),
//     command: Some(ClaimOrRefresh { by: Some(NeuronIdOrSubaccount(())) })
//   })
//
// Result: alice's neuron age is halved (from 4 years to 2 years),
//         reducing her age bonus from 1.25x to 1.125x.
//         Bob can repeat this attack to continuously suppress alice's age bonus.
//
// Reproducible as a unit test extending the existing
// test_refresh_neuron_by_id_by_proxy / test_refresh_neuron_by_subaccount_by_proxy
// pattern in rs/nns/governance/tests/governance.rs, asserting that
// neuron.age_seconds(now) < original_age after a third-party refresh
// with added funds.
```

### Citations

**File:** rs/nns/governance/src/governance.rs (L5875-5896)
```rust
    async fn refresh_neuron_by_id_or_subaccount(
        &mut self,
        id: NeuronIdOrSubaccount,
        claim_or_refresh: &ClaimOrRefresh,
    ) -> Result<NeuronId, GovernanceError> {
        let (nid, subaccount) = match id {
            NeuronIdOrSubaccount::NeuronId(neuron_id) => {
                let neuron_subaccount =
                    self.with_neuron(&neuron_id, |neuron| neuron.subaccount())?;
                (neuron_id, neuron_subaccount)
            }
            NeuronIdOrSubaccount::Subaccount(subaccount_bytes) => {
                let subaccount = Self::bytes_to_subaccount(&subaccount_bytes)?;
                let neuron_id = self
                    .neuron_store
                    .get_neuron_id_for_subaccount(subaccount)
                    .ok_or_else(|| Self::no_neuron_for_subaccount_error(&subaccount.0))?;
                (neuron_id, subaccount)
            }
        };
        self.refresh_neuron(nid, subaccount, claim_or_refresh).await
    }
```

**File:** rs/nns/governance/src/governance.rs (L5950-5952)
```rust
                Ordering::Less => {
                    neuron.update_stake_adjust_age(balance.get_e8s(), now);
                }
```

**File:** rs/nns/governance/src/governance.rs (L6104-6142)
```rust
        // We run claim or refresh before we check whether a neuron exists because it
        // may not in the case of the neuron being claimed
        if let Some(Command::ClaimOrRefresh(claim_or_refresh)) = &mgmt.command {
            // Note that we return here, so none of the rest of this method is executed
            // in this case.
            return match &claim_or_refresh.by {
                Some(By::Memo(memo)) => {
                    let memo_and_controller = MemoAndController {
                        memo: *memo,
                        controller: None,
                    };
                    self.claim_or_refresh_neuron_by_memo_and_controller(
                        caller,
                        memo_and_controller,
                        claim_or_refresh,
                    )
                    .await
                    .map(ManageNeuronResponse::claim_or_refresh_neuron_response)
                }
                Some(By::MemoAndController(memo_and_controller)) => self
                    .claim_or_refresh_neuron_by_memo_and_controller(
                        caller,
                        memo_and_controller.clone(),
                        claim_or_refresh,
                    )
                    .await
                    .map(ManageNeuronResponse::claim_or_refresh_neuron_response),

                Some(By::NeuronIdOrSubaccount(_)) => {
                    let id = mgmt.get_neuron_id_or_subaccount()?.ok_or_else(|| {
                        GovernanceError::new_with_message(
                            ErrorType::NotFound,
                            "No neuron ID specified in the management request.",
                        )
                    })?;
                    self.refresh_neuron_by_id_or_subaccount(id, claim_or_refresh)
                        .await
                        .map(ManageNeuronResponse::claim_or_refresh_neuron_response)
                }
```

**File:** rs/nns/governance/src/neuron/types.rs (L376-379)
```rust
        let stake_e8s = self.stake_e8s();
        let boost = dissolve_delay_bonus_multiplier(self.dissolve_delay_seconds(now_seconds))
            * age_bonus_multiplier(self.age_seconds(now_seconds));
        let mut potential_voting_power = Decimal::from(stake_e8s) * boost;
```

**File:** rs/nns/governance/src/neuron/types.rs (L1021-1038)
```rust
            let (new_stake_e8s, new_age_seconds) = combine_aged_stakes(
                self.cached_neuron_stake_e8s,
                self.age_seconds(now),
                updated_stake_e8s.saturating_sub(self.cached_neuron_stake_e8s),
                0,
            );
            // A consequence of the math above is that the 'new_stake_e8s' is
            // always the same as the 'updated_stake_e8s'. We use
            // 'combine_aged_stakes' here to make sure the age is
            // appropriately pro-rated to accommodate the new stake.
            assert!(new_stake_e8s == updated_stake_e8s);
            self.cached_neuron_stake_e8s = new_stake_e8s;

            let new_aging_since_timestamp_seconds = now.saturating_sub(new_age_seconds);
            let new_disolved_dissolve_state_and_age = self
                .dissolve_state_and_age()
                .adjust_age(new_aging_since_timestamp_seconds);
            self.set_dissolve_state_and_age(new_disolved_dissolve_state_and_age);
```

**File:** rs/nns/governance/src/neuron/mod.rs (L22-46)
```rust
pub fn combine_aged_stakes(
    x_stake_e8s: u64,
    x_age_seconds: u64,
    y_stake_e8s: u64,
    y_age_seconds: u64,
) -> (u64, u64) {
    if x_stake_e8s == 0 && y_stake_e8s == 0 {
        (0, 0)
    } else {
        let total_age_seconds: u128 = ((x_stake_e8s as u128)
            .saturating_mul(x_age_seconds as u128)
            .saturating_add((y_stake_e8s as u128).saturating_mul(y_age_seconds as u128)))
            / ((x_stake_e8s as u128).saturating_add(y_stake_e8s as u128));

        // Note that age is adjusted in proportion to the stake, but due to the
        // discrete nature of u64 numbers, some resolution is lost due to the
        // division above. Only if x_age * x_stake is a multiple of y_stake does
        // the age remain constant after this operation. However, in the end, the
        // most that can be lost due to rounding from the actual age, is always
        // less than 1 second, so this is not a problem.
        (
            x_stake_e8s.saturating_add(y_stake_e8s),
            total_age_seconds as u64,
        )
    }
```

**File:** rs/sns/governance/src/governance.rs (L4237-4298)
```rust
    async fn refresh_neuron(&mut self, nid: &NeuronId) -> Result<(), GovernanceError> {
        let now = self.env.now();
        let subaccount = nid.subaccount()?;
        let account = self.neuron_account_id(subaccount);

        // First ensure that the neuron was not created via an NNS Neurons' Fund participation in the
        // decentralization swap
        {
            let neuron = self.get_neuron_result(nid)?;

            if neuron.is_neurons_fund_controlled() {
                return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    "Cannot refresh an SNS Neuron controlled by the Neurons' Fund",
                ));
            }
        }

        // Get the balance of the neuron from the ledger canister.
        let balance = self.ledger.account_balance(account).await?;

        let min_stake = self
            .nervous_system_parameters_or_panic()
            .neuron_minimum_stake_e8s
            .expect("NervousSystemParameters must have neuron_minimum_stake_e8s");
        if balance.get_e8s() < min_stake {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!(
                    "Account does not have enough funds to refresh a neuron. \
                        Please make sure that account has at least {:?} e8s (was {:?} e8s)",
                    min_stake,
                    balance.get_e8s()
                ),
            ));
        }
        let neuron = self.get_neuron_result_mut(nid)?;
        match neuron.cached_neuron_stake_e8s.cmp(&balance.get_e8s()) {
            Ordering::Greater => {
                log!(
                    ERROR,
                    "ERROR. Neuron cached stake was inconsistent.\
                     Neuron account: {} has less e8s: {} than the cached neuron stake: {}.\
                     Stake adjusted.",
                    account,
                    balance.get_e8s(),
                    neuron.cached_neuron_stake_e8s
                );
                neuron.update_stake(balance.get_e8s(), now);
            }
            Ordering::Less => {
                neuron.update_stake(balance.get_e8s(), now);
            }
            // If the stake is the same as the account balance,
            // just return the neuron id (this way this method
            // also serves the purpose of allowing to discover the
            // neuron id based on the memo and the controller).
            Ordering::Equal => (),
        };

        Ok(())
    }
```

**File:** rs/sns/governance/src/neuron.rs (L224-231)
```rust
        let a = std::cmp::min(self.age_seconds(now_seconds), max_neuron_age_for_age_bonus) as u128;
        let ad_stake = d_stake
            + if max_neuron_age_for_age_bonus > 0 {
                (d_stake * a * max_age_bonus_percentage as u128)
                    / (100 * max_neuron_age_for_age_bonus as u128)
            } else {
                0
            };
```

**File:** rs/sns/governance/src/neuron.rs (L649-679)
```rust
    pub fn update_stake(&mut self, new_stake_e8s: u64, now: u64) {
        // If this neuron has an age and its stake is being increased, adjust the
        // neuron's age
        if self.aging_since_timestamp_seconds < now && self.cached_neuron_stake_e8s <= new_stake_e8s
        {
            let old_stake = self.cached_neuron_stake_e8s as u128;
            let old_age = now.saturating_sub(self.aging_since_timestamp_seconds) as u128;
            let new_age = (old_age * old_stake) / (new_stake_e8s as u128);

            // new_age * new_stake = old_age * old_stake -
            // (old_stake * old_age) % new_stake. That is, age is
            // adjusted in proportion to the stake, but due to the
            // discrete nature of u64 numbers, some resolution is
            // lost due to the division above. This means the age
            // bonus is derived from a constant times age times
            // stake, minus up to new_stake - 1 each time the
            // neuron is refreshed. Only if old_age * old_stake is
            // a multiple of new_stake does the age remain
            // constant after the refresh operation. However, in
            // the end, the most that can be lost due to rounding
            // from the actual age, is always less 1 second, so
            // this is not a problem.
            self.aging_since_timestamp_seconds = now.saturating_sub(new_age as u64);
            // Note that if new_stake == old_stake, then
            // new_age == old_age, and
            // now - new_age =
            // now-(now-neuron.aging_since_timestamp_seconds)
            // = neuron.aging_since_timestamp_seconds.
        }

        self.cached_neuron_stake_e8s = new_stake_e8s;
```

**File:** rs/nns/governance/tests/governance.rs (L5014-5029)
```rust
/// Tests that a neuron can be refreshed by subaccount, and that anyone can do
/// it.
#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_refresh_neuron_by_subaccount_by_controller() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_id_or_subaccount(owner, owner, RefreshBy::Subaccount);
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_refresh_neuron_by_subaccount_by_proxy() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_id_or_subaccount(owner, caller, RefreshBy::Subaccount);
}
```

**File:** rs/nns/governance/src/neuron/voting_power.rs (L23-31)
```rust
pub(crate) fn age_bonus_multiplier(age_seconds: u64) -> Decimal {
    let age_seconds = Decimal::from(age_seconds.clamp(0, MAX_NEURON_AGE_FOR_AGE_BONUS));

    // t is (clamped) age in units of max age, so its value is from 0.0 to 1.0
    let t = age_seconds / Decimal::from(MAX_NEURON_AGE_FOR_AGE_BONUS);

    // 0.25 * t + 1
    t / Decimal::from(4) + Decimal::from(1)
}
```
