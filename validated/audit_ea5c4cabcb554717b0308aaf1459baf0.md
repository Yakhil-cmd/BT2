Audit Report

## Title
Permissionless `ClaimOrRefresh` Permanently Dilutes Neuron Age Bonus via Third-Party Stake Injection - (`rs/nns/governance/src/governance.rs`)

## Summary

`manage_neuron` with `ClaimOrRefresh { by: NeuronIdOrSubaccount }` routes to `refresh_neuron_by_id_or_subaccount`, which performs no caller authorization check. Any unprivileged principal can send ICP to a victim's neuron subaccount on the ledger and then trigger a refresh, causing `update_stake_adjust_age` to permanently dilute the neuron's `aging_since_timestamp_seconds`. This irreversibly reduces the neuron's age bonus, which directly reduces voting power and voting rewards — without the neuron owner's knowledge or consent. The same flaw exists in SNS governance via `claim_or_refresh_neuron_by_memo_and_controller` / `refresh_neuron`.

## Finding Description

**Permissionless entry point (NNS)**

`manage_neuron_internal` in `rs/nns/governance/src/governance.rs` at line 6132 handles `By::NeuronIdOrSubaccount` by calling `refresh_neuron_by_id_or_subaccount(id, claim_or_refresh)` — the `caller` is not forwarded and no authorization check is performed before or inside this call. [1](#0-0) 

`refresh_neuron_by_id_or_subaccount` (lines 5875–5896) accepts any neuron ID or subaccount and delegates directly to `refresh_neuron` with no caller check. [2](#0-1) 

`refresh_neuron` (lines 5900–5962) queries the ledger balance and, when `balance > cached_stake` (`Ordering::Less` branch), unconditionally calls `neuron.update_stake_adjust_age(balance.get_e8s(), now)`. [3](#0-2) 

**Age dilution mechanism**

`update_stake_adjust_age` in `rs/nns/governance/src/neuron/types.rs` calls `combine_aged_stakes` with the incremental stake assigned age=0, producing a weighted-average age strictly less than the original age. The result is written back to `aging_since_timestamp_seconds` permanently. [4](#0-3) 

**Age bonus directly reduces voting power and rewards**

`age_bonus_multiplier` in `rs/nns/governance/src/neuron/voting_power.rs` applies a linear bonus of up to 25% at 4 years of age. This multiplier is applied to every voting power calculation. [5](#0-4) 

It is multiplied into `potential_voting_power` and `deciding_voting_power` in `potential_and_deciding_voting_power`. [6](#0-5) 

**Permissionless behavior explicitly confirmed by tests**

The test suite documents this as intentional: "Tests that a neuron can be refreshed by subaccount, and that anyone can do it." [7](#0-6) 

**Same flaw in SNS governance**

`claim_or_refresh_neuron_by_memo_and_controller` and `refresh_neuron` in `rs/sns/governance/src/governance.rs` perform no caller authorization check and call `neuron.update_stake` which applies the identical age-dilution formula. [8](#0-7) [9](#0-8) 

## Impact Explanation

A neuron that has been non-dissolving for 4 years accumulates the maximum NNS age bonus of 25%. When an attacker sends an equal amount of ICP to the neuron's subaccount and triggers a refresh, the age is halved (weighted average), reducing the age bonus from 25% to ~12.5%. While the victim's absolute voting power increases transiently (more stake), the age bonus is permanently and irreversibly diluted. If the victim subsequently disburses the attacker-injected ICP, they are left with their original stake but a permanently reduced age, resulting in lower voting power and lower voting rewards than before the attack. The lost age cannot be recovered — the neuron must re-age from the diluted baseline, which takes years. This constitutes a significant NNS/SNS governance security impact with concrete, permanent harm to neuron owners' governance influence and reward income.

**Severity: High** — matches "Significant NNS, SNS, or infrastructure security impact with concrete user or protocol harm" and "Unauthorized modification of neurons/governance assets where exploitation requires meaningful per-target work or other constraints."

## Likelihood Explanation

The attack requires the attacker to send ICP to the victim's neuron subaccount. The neuron subaccount is deterministically computable from the public neuron ID. The attacker's ICP is not recoverable (it is locked in the victim's neuron until the victim disburses it), making this a costly griefing attack rather than a profitable one. However, the attack is fully permissionless — no privileged access is required, and any ingress sender can trigger it. It is repeatable: the attacker can send small amounts repeatedly to continuously dilute the age as it re-accumulates, at the cost of additional ICP per iteration. The economic cost to the attacker (permanent ICP loss) constrains likelihood but does not eliminate it, particularly for targeted attacks against high-value neurons or governance adversaries.

## Recommendation

Add an authorization check to `refresh_neuron_by_id_or_subaccount` and `refresh_neuron` in both NNS and SNS governance: only the neuron's controller or authorized hot keys should be permitted to trigger a stake refresh that invokes `update_stake_adjust_age`. Alternatively, decouple the two concerns: allow anyone to sync the cached stake upward (for balance consistency), but only apply the age-dilution side effect when the refresh is initiated by the neuron's controller or a hot key. The `Ordering::Equal` branch already demonstrates that a no-op path exists; a similar no-age-adjustment path could be taken for unauthorized callers when the balance has increased.

## Proof of Concept

**NNS governance (unit test plan):**

1. Create a neuron with `cached_neuron_stake_e8s = S`, `aging_since_timestamp_seconds = T_old` (e.g., 4 years of age, `S = 10 ICP`).
2. Advance time to confirm `age_seconds = 4 years` and `age_bonus_multiplier ≈ 1.25`.
3. As an unrelated attacker principal, add `S` ICP directly to the neuron's ledger subaccount (simulating `driver.add_funds_to_account`).
4. As the attacker principal, call `manage_neuron` with `ClaimOrRefresh { by: NeuronIdOrSubaccount }` targeting the victim's neuron ID.
5. Assert that `aging_since_timestamp_seconds` has advanced (age halved to ~2 years).
6. Assert that `age_bonus_multiplier` has dropped from ~1.25 to ~1.125.
7. Disburse the attacker-injected ICP from the victim's neuron (as the victim/controller).
8. Assert that the neuron now has its original stake `S` but permanently reduced age (~2 years instead of 4), confirming irreversible harm.

The existing test infrastructure in `rs/nns/governance/tests/governance.rs` (`refresh_neuron_by_id_or_subaccount`, `governance_with_staked_neuron`, `driver.add_funds_to_account`) provides all necessary scaffolding to implement this as a deterministic unit test without mainnet interaction.

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

**File:** rs/nns/governance/src/governance.rs (L6132-6141)
```rust
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
```

**File:** rs/nns/governance/src/neuron/types.rs (L377-379)
```rust
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

**File:** rs/sns/governance/src/governance.rs (L4210-4227)
```rust
    async fn claim_or_refresh_neuron_by_memo_and_controller(
        &mut self,
        caller: &PrincipalId,
        memo_and_controller: &MemoAndController,
    ) -> Result<(), GovernanceError> {
        let controller = memo_and_controller.controller.unwrap_or(*caller);
        let memo = memo_and_controller.memo;
        let nid = NeuronId::from(ledger::compute_neuron_staking_subaccount_bytes(
            controller, memo,
        ));
        match self.get_neuron_result(&nid) {
            Ok(neuron) => {
                let nid = neuron.id.as_ref().expect("Neuron must have an id").clone();
                self.refresh_neuron(&nid).await
            }
            Err(_) => self.claim_neuron(nid, &controller).await,
        }
    }
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
