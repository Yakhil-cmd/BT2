### Title
Tip-keyed `active_pox_contract` in `process_stacking_ops` can route a `stack-stx` burn op to a different PoX contract than the cycle-keyed dispatch used for the same cycle's signer set/reward set - ([File: stackslib/src/chainstate/stacks/db/blocks.rs])

### Summary
`StacksChainState::setup_block` computes the PoX contract to which a `StackStxOp` (a burn-chain stacking commitment) is dispatched using the tip-keyed `PoxConstants::active_pox_contract(burn_tip_height)` [1](#0-0) , while the signer-set/reward-set computation for a reward cycle uses the cycle-keyed `PoxConstants::active_pox_contract_for_cycle(first_block_height, reward_cycle)` [2](#0-1) . The code comments explicitly acknowledge these two functions can disagree mid-prepare-phase around the PoX-5 activation boundary [3](#0-2) , and a dedicated regression test (`cycle_predicate_is_stable_across_prepare_phase_for_first_pox5_cycle`) demonstrates the tip-keyed function flips within a single prepare phase while the cycle-keyed function stays stable [4](#0-3) . `process_stacking_ops` was never migrated to the cycle-keyed function, so it can still lock a stacker's STX under the "wrong" PoX contract relative to the contract whose reward set/signer set actually governs that reward cycle.

### Finding Description
`PoxConstants` exposes two version-classification functions:
- `active_pox_contract(burn_height)` — a simple tip-keyed cascade of `>` comparisons against `pox_5_activation_height`, `pox_4_activation_height`, `pox_3_activation_height`, `v1_unlock_height` [5](#0-4) .
- `active_pox_contract_for_cycle(first_block_height, reward_cycle)` — a cycle-keyed function that is explicitly documented as the one that "all cycle-scoped callers (signer-set computation, reward-address resolution) must use," because it is stable across an entire prepare phase, whereas the tip-keyed function "can flip mid-prepare-phase if `pox_5_activation_height` falls inside it" [3](#0-2) .

`NakamotoSigners::check_and_handle_prepare_phase_start` (which computes the .signers reward set / signer set for the upcoming cycle) correctly uses the cycle-keyed function and comments on exactly this hazard: "Tip-keyed `active_pox_contract` is wrong here -- it can flip mid-prepare-phase if `pox_5_activation_height` falls inside it" [2](#0-1) .

However, `StacksChainState::setup_block`, which processes `StackStxOp` burnchain operations (i.e., L1 stacking commitments) for the same block/cycle, still calls the tip-keyed `active_pox_contract(burn_tip_height)` and feeds the resulting contract name into `process_stacking_ops`, which performs the actual `contract-call? stack-stx` against that contract [1](#0-0) ; [6](#0-5) .

Because the tip-keyed function can return `pox-4` for some blocks and `pox-5` for other blocks within the *same* prepare phase (as shown by the test at lines 52-76 of `cycle_dispatch.rs`), while the cycle-keyed function returns a single, stable answer for the whole cycle, a `StackStxOp` burned in a block on one side of the flip boundary is locked/committed against a different PoX contract than the one whose `.signers` reward set and signer weights are computed for that same reward cycle.

### Impact Explanation
If a stacker's `stack-stx` burn-chain operation is processed against `pox-4` while the reward cycle it targets is governed by `pox-5`'s reward set / signer set (because `active_pox_contract_for_cycle` resolved to PoX-5 for that cycle), the stacker's STX gets locked (via `pox-locking`'s v4 handling) but their commitment never lands in the PoX-5 stacking-state/reward-set maps that the coordinator and `.signers` update logic actually consult for that cycle. This is a concrete "value locked but never counted" scenario: STX are locked (temporary freezing, since it still unlocks per pox-4's schedule) without producing the corresponding reward-slot/signing-weight entry, i.e. a commitment that is silently dropped from the cycle's tally — the equality between "STX locked for a cycle" and "STX counted in that cycle's reward/signer set" is broken. Conversely, entries could also be double-processed if a retried/duplicate op crosses the boundary. This falls under "temporary freezing of staked funds" / "signing weight or reward slots not matching locked value" per the impact rubric.

### Likelihood Explanation
This requires `pox_5_activation_height` (or an analogous future activation height) to fall inside a prepare phase, which is a boundary condition that operators/testers must specifically construct (as the existing `cycle_dispatch.rs` test does) — it is not attacker-controlled in the sense of a malicious stacker forcing it, but it is a real consensus-height configuration that occurs during every network-wide PoX version transition. Given that PoX-5 is a newly introduced version in this codebase and the transition logic was patched with a dedicated cycle-keyed function specifically to fix this class of bug in the signer-set path, the burn-op dispatch path in `blocks.rs` appears to be an overlooked spot that was not updated to match, making this a realistic (not purely theoretical) miss during the actual PoX-4→PoX-5 transition window.

### Recommendation
Replace `pox_constants.active_pox_contract(u64::from(burn_tip_height))` in `StacksChainState::setup_block` (and any other reward-cycle-scoped caller that still uses the tip-keyed function around burn-op processing) with `pox_constants.active_pox_contract_for_cycle(first_block_height, reward_cycle)`, computing `reward_cycle` from the burn op's target cycle, so that the contract used to process `StackStxOp`/`DelegateStxOp` burn ops is guaranteed to match the contract whose reward set and signer set govern that same cycle throughout the entire prepare phase.

### Proof of Concept
1. Configure `PoxConstants` such that `pox_5_activation_height` falls inside the prepare phase of reward cycle `N` (mirroring `pox_constants_with_pox_5_at` in `cycle_dispatch.rs` lines 28-35, using `activation = first + N*10 + 9`, a mod-9 prepare-phase block).
2. At the tip corresponding to `activation - 1` (still mod-8 of cycle N, prepare phase), submit a `StackStxOp` for a stacker targeting reward cycle `N+1`. `pox_constants.active_pox_contract(burn_tip_height)` returns `POX_4_NAME` at this block [7](#0-6) , so `process_stacking_ops` locks the stacker's STX via `pox-4`'s `stack-stx`.
3. Meanwhile, `active_pox_contract_for_cycle(first_block_height, N+1)` resolves to `POX_5_NAME` for the whole of cycle `N+1` [8](#0-7) , so `check_and_handle_prepare_phase_start` builds the `.signers` reward set/signer set for cycle `N+1` from `pox-5`'s state.
4. Because the stacker's commitment was written into `pox-4`'s `stacking-state`/`reward-cycle-pox-address-list`, not `pox-5`'s, it is absent from the PoX-5-sourced reward set used to compute cycle `N+1`'s signer weights and reward slots, even though the stacker's STX remains locked. This demonstrates the loss of the "locked ⇒ counted in the governing cycle's reward/signer set" invariant.

### Citations

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L4077-4130)
```rust
    pub fn process_stacking_ops(
        clarity_tx: &mut ClarityTx,
        operations: Vec<StackStxOp>,
        active_pox_contract: &str,
    ) -> Vec<StacksTransactionReceipt> {
        let mut all_receipts = vec![];
        let mainnet = clarity_tx.config.mainnet;
        let cost_so_far = clarity_tx.cost_so_far();
        for stack_stx_op in operations.into_iter() {
            let StackStxOp {
                sender,
                reward_addr,
                stacked_ustx,
                num_cycles,
                block_height,
                txid,
                burn_header_hash,
                ..
            } = &stack_stx_op;

            let mut args = vec![
                Value::UInt(*stacked_ustx),
                // this .expect() should be unreachable since we coerce the hash mode when
                // we parse the StackStxOp from a burnchain transaction
                reward_addr
                    .as_clarity_tuple()
                    .expect("FATAL: stack-stx operation has no hash mode")
                    .into(),
                Value::UInt(u128::from(*block_height)),
                Value::UInt(u128::from(*num_cycles)),
            ];
            // Appending additional signer related arguments for pox-4
            if active_pox_contract == PoxVersions::Pox4.get_name() {
                match StacksChainState::collect_pox_4_stacking_args(&stack_stx_op) {
                    Ok(pox_4_args) => {
                        args.extend(pox_4_args);
                    }
                    Err(e) => {
                        warn!("Skipping StackStx operation for txid: {}, burn_block: {} because of failure in collecting pox-4 stacking args: {}", txid, burn_header_hash, e);
                        continue;
                    }
                }
            }
            let result = clarity_tx.connection().as_transaction(|tx| {
                tx.run_contract_call(
                    &sender.clone().into(),
                    None,
                    &boot_code_id(active_pox_contract, mainnet),
                    "stack-stx",
                    &args,
                    |_, _| None,
                    &ResourceBudget::unlimited(),
                )
            });
```

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L5225-5232)
```rust
        let active_pox_contract = pox_constants.active_pox_contract(u64::from(burn_tip_height));

        // process stacking & transfer operations from burnchain ops
        tx_receipts.extend(StacksChainState::process_stacking_ops(
            &mut clarity_tx,
            stacking_burn_ops.clone(),
            active_pox_contract,
        ));
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L971-982)
```rust
        // Dispatch must be cycle-stable: every block of this prepare phase
        // must agree on which pox contract supplies cycle_of_prepare_phase's
        // signer set, regardless of which block first triggers the update.
        // Tip-keyed `active_pox_contract` is wrong here -- it can flip
        // mid-prepare-phase if pox_5_activation_height falls inside it.
        let active_pox_contract =
            pox_constants.active_pox_contract_for_cycle(first_block_height, cycle_of_prepare_phase);

        let Some(current_pox_version) = PoxVersions::lookup_by_name(active_pox_contract) else {
            debug!("Active PoX contract is not a recognized version, skipping .signers updates");
            return Ok(None);
        };
```

**File:** stackslib/src/burnchains/mod.rs (L388-418)
```rust
    /// Returns the PoX contract that is "active" at the given burn block height
    fn static_active_pox_contract(
        v1_unlock_height: u64,
        pox_3_activation_height: u64,
        pox_4_activation_height: u64,
        pox_5_activation_height: u64,
        burn_height: u64,
    ) -> &'static str {
        if burn_height > pox_5_activation_height {
            POX_5_NAME
        } else if burn_height > pox_4_activation_height {
            POX_4_NAME
        } else if burn_height > pox_3_activation_height {
            POX_3_NAME
        } else if burn_height > v1_unlock_height {
            POX_2_NAME
        } else {
            POX_1_NAME
        }
    }

    /// Returns the PoX contract that is "active" at the given burn block height
    pub fn active_pox_contract(&self, burn_height: u64) -> &'static str {
        Self::static_active_pox_contract(
            u64::from(self.v1_unlock_height),
            u64::from(self.pox_3_activation_height),
            u64::from(self.pox_4_activation_height),
            u64::from(self.pox_5_activation_height),
            burn_height,
        )
    }
```

**File:** stackslib/src/burnchains/mod.rs (L420-434)
```rust
    /// Returns the PoX contract controlling the signer set and reward set
    /// for `reward_cycle`.
    ///
    /// Cycle-keyed counterpart to `active_pox_contract`.
    ///
    /// All cycle-scoped callers (signer-set computation, reward-address
    /// resolution) must use this; only tip-scoped callers (RPC, "what's
    /// live now") use the burn-height variant.
    ///
    /// The PoX-5 branch is derived from `first_pox_waterfall_block` so that
    /// `active_pox_contract_for_cycle` and the waterfall block-commit /
    /// nakamoto-cycle-start predicates agree on a single boundary.
    ///
    /// For pre-PoX-5 transitions the existing tip-keyed answer is preserved by
    /// evaluating at the cycle's mod-1 (classic reward-phase start) block.
```

**File:** stackslib/src/burnchains/tests/cycle_dispatch.rs (L52-76)
```rust
#[test]
fn cycle_predicate_is_stable_across_prepare_phase_for_first_pox5_cycle() {
    // Place activation deep inside the prepare phase that sets up the
    // first PoX-5 cycle. Tip-keyed `active_pox_contract` would return
    // POX_4 for some blocks and POX_5 for others; the cycle-keyed
    // predicate must answer consistently for the cycle as a whole.
    let first = 100u64;
    // offset 9 of cycle 3 = a prepare-phase block of cycle 3 (mod-9).
    let activation = first + 3 * 10 + 9;
    let c = pox_constants_with_pox_5_at(activation as u32);

    // Tip-keyed dispatch genuinely disagrees across the prepare phase:
    // mod-8 of cycle 3 returns POX_4 (burn_height < activation), but
    // mod-0 of cycle 4 returns POX_5 (burn_height > activation).
    let prepare_start = first + 3 * 10 + 8;
    let prepare_end = first + 4 * 10; // mod-0 of cycle 4
    assert_eq!(c.active_pox_contract(prepare_start), POX_4_NAME);
    assert_eq!(c.active_pox_contract(prepare_end), POX_5_NAME);

    // The cycle-keyed predicate is the single source of truth.
    // first_pox_waterfall_block puts cycle 3 as the last classic cycle
    // (it contains the activation height), so cycle 4 is first PoX-5.
    assert_eq!(c.active_pox_contract_for_cycle(first, 3), POX_4_NAME);
    assert_eq!(c.active_pox_contract_for_cycle(first, 4), POX_5_NAME);
}
```
