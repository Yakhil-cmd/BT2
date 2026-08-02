No vulnerability found for this question.

**Analysis:** The `block_gas_limit()` function in `limit_processor.rs` is a pure, deterministic function of the processor's own state (`block_gas_limit_override` and `block_gas_limit_type`), computing `override_limit.min(onchain_limit)` when both are present [1](#0-0) . Both `should_end_block_parallel` and `should_end_block_sequential` route through the identical `should_end_block(mode)` implementation, which calls this same `block_gas_limit()` method with no path-dependent branching [2](#0-1) . There is no way for the clamp to differ between parallel and sequential execution since they share the same code and the same `BlockGasLimitProcessor` instance state — there is no discrepancy to exploit.

Furthermore, this logic governs block-level early-halting of BlockSTM execution (a liveness/performance/gas-accounting mechanism), not transaction admission, sender/signer binding, fee-payer authentication, or module-context validation. It has no connection to mempool, vm-validator, or authenticator checks that determine whether a transaction is admitted under the correct sender/signer/fee-payer. The existing test `test_override_cannot_exceed_onchain_limit` already validates that the override can only lower, never raise, the effective on-chain cap [3](#0-2) , and this clamping behavior is invariant regardless of execution mode.

This does not meet the Admission Impact Gate criteria (no sender/signer/fee-payer confusion, no replay/expiry/sequence/chain-id issue, no authenticator/approval-set defect) and is outside the transaction admission boundary described in the Boundary Conditions.

### Citations

**File:** aptos-move/block-executor/src/limit_processor.rs (L141-154)
```rust
    fn block_gas_limit(&self) -> Option<u64> {
        // The override is proposer-supplied (via the payload's TxnAndGasLimits) and
        // is not validated against the on-chain cap during consensus payload
        // verification. Clamp it to the on-chain limit so a Byzantine proposer
        // cannot raise the per-block gas cap; the override may only lower it.
        match (
            self.block_gas_limit_override,
            self.block_gas_limit_type.block_gas_limit(),
        ) {
            (Some(override_limit), Some(onchain_limit)) => Some(override_limit.min(onchain_limit)),
            (Some(override_limit), None) => Some(override_limit),
            (None, onchain_limit) => onchain_limit,
        }
    }
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L156-196)
```rust
    fn should_end_block(&mut self, mode: &str) -> bool {
        if let Some(per_block_gas_limit) = self.block_gas_limit() {
            // When the accumulated block gas of the committed txns exceeds
            // PER_BLOCK_GAS_LIMIT, early halt BlockSTM.
            let accumulated_block_gas = self.get_effective_accumulated_block_gas();
            if accumulated_block_gas >= per_block_gas_limit {
                counters::EXCEED_PER_BLOCK_GAS_LIMIT_COUNT.inc_with(&[mode]);
                info!(
                    "[BlockSTM]: execution ({}) early halted due to \
                    accumulated_block_gas {} >= PER_BLOCK_GAS_LIMIT {}",
                    mode, accumulated_block_gas, per_block_gas_limit,
                );
                self.halted_by = Some("gas");
                return true;
            }
        }

        if let Some(per_block_output_limit) = self.block_gas_limit_type.block_output_limit() {
            let accumulated_output = self.get_accumulated_approx_output_size();
            if accumulated_output >= per_block_output_limit {
                counters::EXCEED_PER_BLOCK_OUTPUT_LIMIT_COUNT.inc_with(&[mode]);
                info!(
                    "[BlockSTM]: execution ({}) early halted due to \
                    accumulated_output {} >= PER_BLOCK_OUTPUT_LIMIT {}",
                    mode, accumulated_output, per_block_output_limit,
                );
                self.halted_by = Some("output_size");
                return true;
            }
        }

        false
    }

    pub(crate) fn should_end_block_parallel(&mut self) -> bool {
        self.should_end_block(counters::Mode::PARALLEL)
    }

    pub(crate) fn should_end_block_sequential(&mut self) -> bool {
        self.should_end_block(counters::Mode::SEQUENTIAL)
    }
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L410-433)
```rust
    #[test]
    fn test_override_cannot_exceed_onchain_limit() {
        // Onchain effective cap is 100. A (potentially Byzantine) proposer-supplied
        // override of u64::MAX must be clamped to 100, not honored as-is.
        let block_gas_limit = BlockGasLimitType::ComplexLimitV1 {
            effective_block_gas_limit: 100,
            execution_gas_effective_multiplier: 1,
            io_gas_effective_multiplier: 1,
            conflict_penalty_window: 1,
            use_module_publishing_block_conflict: false,
            block_output_limit: None,
            include_user_txn_size_in_block_output: true,
            add_block_limit_outcome_onchain: false,
            use_granular_resource_group_conflicts: false,
        };

        let mut processor = TestProcessor::new(block_gas_limit, Some(u64::MAX), 10);

        processor.accumulate_fee_statement(execution_fee(60), None, None);
        assert!(!processor.should_end_block_parallel());
        // After 110 raw gas, the clamped (=100) onchain cap must trigger early halt.
        processor.accumulate_fee_statement(execution_fee(50), None, None);
        assert!(processor.should_end_block_parallel());
    }
```
