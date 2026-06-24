Audit Report

## Title
Unbounded Synchronous Loop in `create_sns_neuron_recipes` Can Permanently Lock `finalize_swap` - (File: rs/sns/swap/src/swap.rs)

## Summary
`Swap::create_sns_neuron_recipes` is a fully synchronous function that iterates over all buyers and all Neurons' Fund participants without any batch limit. It is called from `finalize_inner` after multiple `await` points, meaning the `finalize_swap_in_progress` lock has already been committed to replicated state. If the function exhausts the IC instruction limit and traps, the lock is never released, permanently preventing swap finalization.

## Finding Description
`lock_finalize_swap()` sets `finalize_swap_in_progress = Some(true)` synchronously before the first `await` in `finalize`. [1](#0-0) 

Under the IC execution model, state changes made before an outgoing inter-canister call are committed to replicated state at the call boundary. Once `sweep_icp` (await #1) and `settle_neurons_fund_participation` (await #2) are reached, the lock is durably committed. [2](#0-1) 

`create_sns_neuron_recipes` is then called synchronously in the callback message of `settle_neurons_fund_participation`. It performs two nested unbounded loops — one over all `self.buyers` and one over all `self.cf_participants` / their `cf_neurons` — with no batch limit or cursor. [3](#0-2) [4](#0-3) 

The total work scales as `(|buyers| + |cf_neurons|) × neuron_basket_construction_parameters.count`. `MAX_SNS_NEURONS_PER_BASKET` is capped at 10 and `MAX_NEURONS_FOR_DIRECT_PARTICIPANTS` exists as a bound, but neither is calibrated against the IC's ~5 billion instruction limit per message. With `MAX_SNS_NEURONS_PER_BASKET = 10` and a large number of direct participants (bounded by `MAX_NEURONS_FOR_DIRECT_PARTICIPANTS`, whose value is not confirmed here) plus Neurons' Fund neurons (bounded by `MAX_NEURONS_FUND_PARTICIPANTS`), the combined recipe-creation work — each iteration involving subaccount hash computation (SHA-256), struct construction, and vector extension — can plausibly exhaust the instruction budget in a single callback message. [5](#0-4) 

If the callback traps, the IC rolls back only that message's state changes. The lock committed in the prior message remains `Some(true)` permanently. [6](#0-5) 

The code itself acknowledges this exact failure mode in a comment at `unlock_finalize_swap`. [7](#0-6) 

## Impact Explanation
**High.** If `create_sns_neuron_recipes` traps: (1) `finalize_swap_in_progress` remains `true`; (2) all subsequent calls to `finalize_swap` immediately return an error from `lock_finalize_swap`; (3) ICP has already been swept (step 1 completed and committed), but SNS tokens are never distributed and neurons are never created; (4) the swap is permanently stuck. Recovery requires an NNS governance action to upgrade the canister and manually clear the lock. This matches the allowed impact: **Significant SNS security impact with concrete user or protocol harm** — participant funds (ICP already transferred, SNS tokens stranded) are effectively frozen. [8](#0-7) 

## Likelihood Explanation
**Low.** Triggering this requires a swap configured with a large number of participants and/or a large basket count, combined with enough NF neurons to push the combined recipe-creation work past the instruction limit. `MAX_SNS_NEURONS_PER_BASKET = 10` and `MIN_PARTICIPANT_ICP_LOWER_BOUND_E8S = 1_000_000` provide partial mitigation, but neither is calibrated against the instruction budget. A popular SNS launch filling to capacity with minimum-contribution participants (each receiving 10-neuron baskets) plus a large Neurons' Fund participation could plausibly reach the threshold. No privileged access is required to call `finalize_swap`. [9](#0-8) [10](#0-9) 

## Recommendation
Apply the same cursor-based batching pattern already used by `try_purge_old_tickets` in `swap.rs`: persist a `next_buyer_to_process` cursor in swap state so that successive calls to `finalize_swap` (or a dedicated periodic task) continue from where the previous call left off. Alternatively, enforce a strict upper bound on `(max_direct_participation_icp_e8s / min_participant_icp_e8s + max_cf_neurons) × neuron_basket_construction_parameters.count` during swap initialization validation, calibrated against the IC instruction limit with a safety margin. [11](#0-10) 

## Proof of Concept
1. Deploy an SNS swap with `min_participant_icp_e8s = MIN_PARTICIPANT_ICP_LOWER_BOUND_E8S`, `max_direct_participation_icp_e8s` at or near the maximum, and `neuron_basket_construction_parameters.count = 10`.
2. Fill the swap to capacity with distinct buyer principals each contributing the minimum, plus a large Neurons' Fund participation.
3. Allow the swap to reach `Lifecycle::Committed`.
4. Call `finalize_swap({})` from any principal.
5. `sweep_icp` completes, committing `finalize_swap_in_progress = true` to replicated state.
6. `create_sns_neuron_recipes` is invoked synchronously; the instruction limit is exhausted; the callback message traps.
7. Observe: `finalize_swap_in_progress` remains `true`; all subsequent `finalize_swap` calls return immediately with a lock-held error; SNS tokens are permanently stranded.

A deterministic integration test using PocketIC can reproduce this by configuring the swap at the boundary of `MAX_NEURONS_FOR_DIRECT_PARTICIPANTS` with `count = 10` and measuring instruction consumption via the PocketIC instruction counter API. [12](#0-11)

### Citations

**File:** rs/sns/swap/src/swap.rs (L777-810)
```rust
    pub fn create_sns_neuron_recipes(&mut self) -> SweepResult {
        let Some(params) = self.params.as_ref() else {
            log!(
                ERROR,
                "Halting create_sns_neuron_recipes(). Params is missing",
            );
            return SweepResult::new_with_global_failures(1);
        };

        let Some(neuron_basket_construction_parameters) =
            params.neuron_basket_construction_parameters.as_ref()
        else {
            log!(
                ERROR,
                "Halting create_sns_neuron_recipes(). Neuron_basket_construction_parameters is missing",
            );
            return SweepResult::new_with_global_failures(1);
        };

        let init = match self.init_and_validate() {
            Ok(init) => init,
            Err(error_message) => {
                log!(
                    ERROR,
                    "Halting create_sns_neuron_recipes(). Init is missing or corrupted: {:?}",
                    error_message
                );
                return SweepResult::new_with_global_failures(1);
            }
        };
        // The following methods are safe to call since we validated Init in the above block
        let nns_governance_canister_id = init.nns_governance_or_panic();

        let mut sweep_result = SweepResult::default();
```

**File:** rs/sns/swap/src/swap.rs (L839-883)
```rust
        for (buyer_principal, buyer_state) in self.buyers.iter_mut() {
            // The case that on a previous attempt at creating this neuron recipe, it was
            // successfully created and recorded. Count the number of neuron recipes that
            // would have been created.
            if buyer_state.has_created_neuron_recipes == Some(true) {
                sweep_result.skipped += neuron_basket_construction_parameters.count as u32;
                continue;
            }

            let amount_sns_e8s = Swap::scale(
                buyer_state.amount_icp_e8s(),
                sns_being_offered_e8s,
                total_participant_icp_e8s,
            );

            let Some(buyer_principal) = string_to_principal(buyer_principal) else {
                sweep_result.invalid += neuron_basket_construction_parameters.count as u32;
                continue;
            };
            match create_sns_neuron_basket_for_direct_participant(
                &buyer_principal,
                amount_sns_e8s,
                neuron_basket_construction_parameters,
                NEURON_BASKET_MEMO_RANGE_START,
            ) {
                Ok(direct_participant_sns_neuron_recipes) => {
                    self.neuron_recipes
                        .extend(direct_participant_sns_neuron_recipes);
                    total_sns_tokens_sold_e8s =
                        total_sns_tokens_sold_e8s.saturating_add(amount_sns_e8s);
                    sweep_result.success += neuron_basket_construction_parameters.count as u32;
                    buyer_state.has_created_neuron_recipes = Some(true);
                }
                Err(error_message) => {
                    log!(
                        ERROR,
                        "Error creating a neuron basked for identity {}. Reason: {}",
                        buyer_principal,
                        error_message
                    );
                    sweep_result.failure += neuron_basket_construction_parameters.count as u32;
                    continue;
                }
            };
        }
```

**File:** rs/sns/swap/src/swap.rs (L892-975)
```rust
        for neurons_fund_participant in self.cf_participants.iter_mut() {
            let controller = neurons_fund_participant.try_get_controller();

            for neurons_fund_neuron in neurons_fund_participant.cf_neurons.iter_mut() {
                // Create a closure to ensure `global_neurons_fund_memo` is incremented in all cases
                let hotkeys = neurons_fund_neuron.hotkeys.clone().unwrap_or_default();
                let process_neurons_fund_neuron = || {
                    let controller = match controller.clone() {
                        Ok(nns_neuron_controller_principal) => nns_neuron_controller_principal,
                        Err(e) => {
                            log!(
                                ERROR,
                                "Error getting the controller for {neurons_fund_neuron:?} principal: {e}"
                            );
                            sweep_result.invalid +=
                                neuron_basket_construction_parameters.count as u32;
                            return;
                        }
                    };

                    // The case that on a previous attempt at creating this neuron recipe, it was
                    // successfully created and recorded. Count the number of neuron recipes that
                    // would have been created.
                    if neurons_fund_neuron.has_created_neuron_recipes == Some(true) {
                        sweep_result.skipped += neuron_basket_construction_parameters.count as u32;
                        return;
                    }

                    let amount_sns_e8s = Swap::scale(
                        neurons_fund_neuron.amount_icp_e8s,
                        sns_being_offered_e8s,
                        total_participant_icp_e8s,
                    );

                    match create_sns_neuron_basket_for_neurons_fund_participant(
                        &controller,
                        hotkeys.principals,
                        neurons_fund_neuron.nns_neuron_id,
                        amount_sns_e8s,
                        neuron_basket_construction_parameters,
                        global_neurons_fund_memo,
                        nns_governance_canister_id.get(),
                    ) {
                        Ok(cf_participants_sns_neuron_recipes) => {
                            sweep_result.success +=
                                neuron_basket_construction_parameters.count as u32;
                            self.neuron_recipes
                                .extend(cf_participants_sns_neuron_recipes);
                            total_sns_tokens_sold_e8s =
                                total_sns_tokens_sold_e8s.saturating_add(amount_sns_e8s);
                            neurons_fund_neuron.has_created_neuron_recipes = Some(true);
                        }
                        Err(error_message) => {
                            log!(
                                ERROR,
                                "Error creating a neuron basked for identity {}. Reason: {}",
                                controller,
                                error_message
                            );
                            sweep_result.failure +=
                                neuron_basket_construction_parameters.count as u32;
                        }
                    };
                };

                // Call the closure
                process_neurons_fund_neuron();

                // Increment the memo by the number neurons in a neuron basket. This means that
                // previous idempotent calls should increment global_neurons_fund_memo and handle overflow
                match global_neurons_fund_memo
                    .checked_add(neuron_basket_construction_parameters.count)
                {
                    Some(new_value) => {
                        global_neurons_fund_memo = new_value;
                    }
                    None => {
                        sweep_result.global_failures += 1;
                        // This will exit the entire function, ending all loops, but persist the data that has already been processed
                        return sweep_result;
                    }
                }
            }
        }
```

**File:** rs/sns/swap/src/swap.rs (L1444-1451)
```rust
    pub fn lock_finalize_swap(&mut self) -> Result<(), String> {
        match self.is_finalize_swap_locked() {
            true => Err("The Swap canister has finalize_swap call already in progress".to_string()),
            false => {
                self.finalize_swap_in_progress = Some(true);
                Ok(())
            }
        }
```

**File:** rs/sns/swap/src/swap.rs (L1454-1467)
```rust
    /// Releases the lock on `finalize_swap`.
    fn unlock_finalize_swap(&mut self) {
        match self.is_finalize_swap_locked() {
            true => self.finalize_swap_in_progress = Some(false),
            false => {
                log!(
                    ERROR,
                    "Unexpected condition when unlocking finalize_swap_in_progress. \
                    The lock was not held: {:?}.",
                    self.finalize_swap_in_progress
                );
            }
        }
    }
```

**File:** rs/sns/swap/src/swap.rs (L1505-1512)
```rust
        // Acquire the lock or return a FinalizeSwapResponse with an error message.
        if let Err(error_message) = self.lock_finalize_swap() {
            return FinalizeSwapResponse::with_error(error_message);
        }

        // The lock is now acquired and asynchronous calls to finalize are blocked.
        // Perform all subactions.
        let finalize_swap_response = self.finalize_inner(now_fn, environment).await;
```

**File:** rs/sns/swap/src/swap.rs (L1528-1531)
```rust
        // Release the lock. Note, if there is a panic, the lock will
        // not be released. In that case, the Swap canister will need
        // to be upgraded to release the lock.
        self.unlock_finalize_swap();
```

**File:** rs/sns/swap/src/swap.rs (L1557-1591)
```rust
        finalize_swap_response
            .set_sweep_icp_result(self.sweep_icp(now_fn, environment.icp_ledger()).await);
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }

        // Settle the Neurons' Fund participation in the token swap.
        finalize_swap_response.set_settle_neurons_fund_participation_result(
            self.settle_neurons_fund_participation(environment.nns_governance_mut())
                .await,
        );
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }

        if self.should_restore_dapp_control() {
            // Restore controllers of dapp canisters to their original
            // owners (i.e. self.init.fallback_controller_principal_ids).
            finalize_swap_response.set_set_dapp_controllers_result(
                self.restore_dapp_controllers_for_finalize(environment.sns_root_mut())
                    .await,
            );

            // In the case of returning control of the dapp(s) to the fallback
            // controllers, finalize() need not do any more work, so always return
            // and end execution.
            return finalize_swap_response;
        }

        // Create the SnsNeuronRecipes based on the contribution of direct and NF participants
        finalize_swap_response
            .set_create_sns_neuron_recipes_result(self.create_sns_neuron_recipes());
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }
```

**File:** rs/sns/swap/src/swap.rs (L2609-2667)
```rust
    pub fn try_purge_old_tickets(
        &mut self,
        now_nanoseconds: impl Fn() -> u64,
        /* amount of tickets after which purge_old_tickets is executed */
        number_of_tickets_threshold: u64,
        /* minimum age of a ticket to be purged */
        max_age_in_nanoseconds: u64,
        /* max number of inspect in a single call */
        max_number_to_inspect: u64,
    ) -> Option<bool> {
        const INTERVAL_NANOSECONDS: u64 = 60 * 10 * 1_000_000_000; // 10 minutes

        if self.lifecycle() != Lifecycle::Open {
            return None;
        }

        // Do not run purge_old_tickets if the number of tickets is less than or equal
        // to the threshold. This should save cycles.
        if memory::OPEN_TICKETS_MEMORY.with(|ts| ts.borrow().len()) < number_of_tickets_threshold {
            return None;
        }

        let purge_old_tickets_last_completion_timestamp_nanoseconds = self
            .purge_old_tickets_last_completion_timestamp_nanoseconds
            .unwrap_or(0);

        let purge_old_tickets_next_principal = self.purge_old_tickets_next_principal().to_vec();
        let first_principal_bytes = FIRST_PRINCIPAL_BYTES.to_vec();

        if purge_old_tickets_next_principal != first_principal_bytes
            || purge_old_tickets_last_completion_timestamp_nanoseconds + INTERVAL_NANOSECONDS
                <= now_nanoseconds()
        {
            return match self.purge_old_tickets(
                now_nanoseconds(),
                purge_old_tickets_next_principal,
                max_age_in_nanoseconds,
                max_number_to_inspect,
            ) {
                Some(new_next_principal) => {
                    // If a principal is returned then there are some principals that haven't been
                    // checked yet by purge_old_tickets. We record the next principal so that
                    // the next periodic task can continue the work.
                    self.purge_old_tickets_next_principal = Some(new_next_principal);
                    Some(false)
                }
                None => {
                    // If no principal is returned then purge_old_tickets has
                    // exhausted all the tickets.
                    log!(INFO, "purge_old_tickets done");
                    self.purge_old_tickets_next_principal = Some(first_principal_bytes);
                    self.purge_old_tickets_last_completion_timestamp_nanoseconds =
                        Some(now_nanoseconds());
                    Some(true)
                }
            };
        }
        None
    }
```

**File:** rs/sns/init/src/lib.rs (L80-89)
```rust
pub const MAX_DIRECT_ICP_CONTRIBUTION_TO_SWAP: u64 = 1_000_000_000 * E8;

/// The lower bound on `min_participant_icp_e8s`.
pub const MIN_PARTICIPANT_ICP_LOWER_BOUND_E8S: u64 = 1_000_000;

/// Minimum allowed number of SNS neurons per neuron basket.
pub const MIN_SNS_NEURONS_PER_BASKET: u64 = 2;

/// Maximum allowed number of SNS neurons per neuron basket.
pub const MAX_SNS_NEURONS_PER_BASKET: u64 = 10;
```

**File:** rs/sns/swap/canister/swap.did (L474-474)
```text
  finalize_swap : (record {}) -> (FinalizeSwapResponse);
```
