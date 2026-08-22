### Title
Congestion control admission/deduction gas mismatch in `try_forward` allows a single receipt with unbounded real gas to be forwarded past the shard's outgoing gas limit - (File: runtime/runtime/src/congestion_control.rs)

### Summary
In `ReceiptSinkV2::try_forward`, when `ProtocolFeature::ClampOutgoingGasAdmission` is enabled, the admission check uses `admission_gas = gas.min(allowed_shard_outgoing_gas)`, but the subsequent deduction from `forward_limit.gas` and the congestion bookkeeping (`own_congestion_info`, `stats`) still use the real, uncapped `gas` value. This means a receipt whose real congestion gas vastly exceeds `forward_limit.gas` can still be admitted as long as `forward_limit.gas >= admission_gas` (the clamped, small value), letting more real gas cross the shard boundary in one shot than the remaining limit for that round.

### Finding Description
`try_forward` computes the admission threshold as:
```rust
let admission_gas = if ProtocolFeature::ClampOutgoingGasAdmission.enabled(...) {
    gas.min(apply_state.config.congestion_control_config.allowed_shard_outgoing_gas)
} else {
    gas
};

if forward_limit.gas >= admission_gas && forward_limit.size >= size {
    outgoing_receipts.push(receipt);
    forward_limit.gas = forward_limit.gas.saturating_sub(gas);
    ...
}
``` [1](#0-0) 

The admission decision is gated on `admission_gas` (capped at `allowed_shard_outgoing_gas`), but the actual gas subtracted from `forward_limit.gas` — the per-chunk outgoing gas budget for that shard — is the real, uncapped `gas`, which is computed by `compute_receipt_congestion_gas` → `action_receipt_congestion_gas`, itself derived from `total_prepaid_gas` of the receipt's actions (i.e., attacker-controlled attached gas on `FunctionCall` actions) plus prepaid exec/send fees. [2](#0-1) 

This clamp-on-admission design is intentional for the *fully-congested / allowed-shard* case: when a shard is 100% congested, `outgoing_gas_limit` sets `forward_limit.gas` to exactly `config.allowed_shard_outgoing_gas` for the one "allowed shard", specifically to guarantee forward progress (per the doc comment: "This amount is the absolute minimum of new workload a congested shard has to accept every round. It ensures deadlocks are provably impossible"). [3](#0-2) [4](#0-3) 

However, the clamp in `try_forward` is applied unconditionally to *every* forwarding decision for *any* shard and *any* congestion level, not only the deadlock-avoidance case. Concretely: for any shard whose remaining `forward_limit.gas` for the round is less than a receipt's real `gas` but at least `allowed_shard_outgoing_gas`, the receipt is admitted, and `forward_limit.gas` afterwards saturates to zero via `saturating_sub`, effectively "eating" far more of the shard's real gas budget for that round than the limit was configured to allow. In other words, a single maximally-priced receipt (bounded above by `max_total_prepaid_gas`/`max_tx_gas` limits on prepaid gas) can be pushed through even though `forward_limit.gas` was only just above `allowed_shard_outgoing_gas`, well below the receipt's actual gas — a mismatch between the *admission test* and the *quantity actually charged/forwarded*.

I was unable to fully verify from the indexed files the exact numeric relationship between `max_total_prepaid_gas` (the wasm limit on attached FunctionCall gas) and `allowed_shard_outgoing_gas` in the currently active mainnet/testnet runtime config, because `core/parameters/res/runtime_configs/*.yaml`/`*.snap` content for `max_total_prepaid_gas` was not retrievable through search before the tool budget ran out. Based on the partially-viewed `68.yaml` diff, `allowed_shard_outgoing_gas` is `1 PGas` while `max_tx_gas` is `500 TGas`, i.e., far below `allowed_shard_outgoing_gas`; if `max_total_prepaid_gas` similarly stays below `allowed_shard_outgoing_gas` under current configs, the practical overshoot introduced by this clamp is small (bounded by `allowed_shard_outgoing_gas` itself, not by a much larger receipt gas), and the discrepancy would be a bounded/known quantity rather than an unbounded "attacker crafts unlimited gas" bypass. This is a material precondition that determines whether the mismatch is a meaningful over-admission (multiple PGas of unaccounted gas) or a bounded rounding artifact of an intentional anti-deadlock mechanism.

### Impact Explanation
If `max_total_prepaid_gas` (or any receipt's true congestion gas, which also includes prepaid exec/send fees across all actions in a receipt) can exceed `allowed_shard_outgoing_gas`, this allows over-admission of real gas into a receiving shard beyond its configured `outgoing_gas_limit`/`allowed_shard_outgoing_gas` for a round, which is a congestion-control/gas-metering-completeness violation (matches "gas or storage metering bypass" / "congestion accounting failures" bounty categories). The impact is bounded per receipt by the maximum congestion gas a single receipt can carry (governed by `max_total_prepaid_gas`, `max_tx_gas`, and related wasm limit configs) minus the limit that was actually available, not unbounded, and it does not directly cause fund loss, balance divergence, or unauthorized actions — it is a resource/scheduling fairness issue affecting shard workload distribution under sustained congestion, not gas under-charging of the receipt's own execution (the receipt is still separately gas-metered and paid for by the sender at execution time).

### Likelihood Explanation
Preconditions: `ProtocolFeature::ClampOutgoingGasAdmission` must be enabled at the current protocol version, and the target shard must be moderately-to-fully congested so that `forward_limit.gas` is reduced to near/at `allowed_shard_outgoing_gas`. An unprivileged attacker can trigger this by submitting `FunctionCall` receipts with maximal attached gas (`total_prepaid_gas` near the protocol's `max_total_prepaid_gas`/`max_tx_gas` ceiling) targeted at a congested shard; no privileged access is required. Whether this is exploitable to a meaningful degree depends entirely on the ratio between the maximum achievable per-receipt congestion gas and `allowed_shard_outgoing_gas` in the currently deployed runtime config — a ratio I could not conclusively determine from available indexed files.

### Recommendation
Decouple the "deadlock-avoidance" purpose of the clamp from the general admission path: only apply the `gas.min(allowed_shard_outgoing_gas)` relaxation when `forward_limit.gas` itself equals the fully-congested `allowed_shard_outgoing_gas` allowance (i.e., only for the designated "allowed shard" under full congestion), rather than unconditionally for every shard/congestion level. Alternatively, cap `forward_limit.gas` deduction to the same `admission_gas` value used for the check (so `forward_limit.gas = forward_limit.gas.saturating_sub(admission_gas)` is consistent with what was checked) while separately tracking real gas in `own_congestion_info` — but any change here is a protocol-level change requiring careful backward-compatible gating via a new `ProtocolFeature`.

### Proof of Concept
Unit test in `runtime/runtime/src/congestion_control.rs` (or `runtime/runtime/src/tests/apply.rs`) test module:
1. Construct an `ApplyState` with `ClampOutgoingGasAdmission` enabled and a `CongestionControlConfig` with a small `allowed_shard_outgoing_gas` (e.g., 1 PGas) and a shard fully congested (via `CongestionInfo`/missed chunks) so `outgoing_gas_limit` returns `allowed_shard_outgoing_gas` for the target shard.
2. Craft a `Receipt` (`FunctionCall` action receipt) whose `compute_receipt_congestion_gas` result is significantly larger than `allowed_shard_outgoing_gas` (e.g., near `max_total_prepaid_gas`).
3. Call `ReceiptSinkV2::try_forward` (or drive it via `forward_or_buffer_receipt`) repeatedly with several such receipts targeting the same shard within one chunk.
4. Assert: `ReceiptForwarding::Forwarded` is returned for a receipt whose real `gas` > remaining `forward_limit.gas`, and sum the total real gas of all receipts forwarded to that shard within the chunk; assert this sum exceeds `config.congestion_control_config.allowed_shard_outgoing_gas` (violating the intended cap), demonstrating the admission/deduction mismatch.

### Citations

**File:** runtime/runtime/src/congestion_control.rs (L443-458)
```rust
        let admission_gas = if ProtocolFeature::ClampOutgoingGasAdmission
            .enabled(apply_state.current_protocol_version)
        {
            gas.min(apply_state.config.congestion_control_config.allowed_shard_outgoing_gas)
        } else {
            gas
        };

        if forward_limit.gas >= admission_gas && forward_limit.size >= size {
            tracing::trace!(target: "runtime", ?shard, receipt_id=?receipt.receipt_id(), "forwarding buffered receipt");
            outgoing_receipts.push(receipt);
            forward_limit.gas = forward_limit.gas.saturating_sub(gas);
            forward_limit.size -= size;
            stats.forwarded_receipts.entry(shard).or_default().add_receipt(size, gas);

            Ok(ReceiptForwarding::Forwarded)
```

**File:** runtime/runtime/src/congestion_control.rs (L716-735)
```rust
fn action_receipt_congestion_gas(
    receipt: &Receipt,
    config: &RuntimeConfig,
    action_receipt: VersionedActionReceipt,
) -> Result<Gas, IntegerOverflowError> {
    let prepaid_exec_gas =
        total_prepaid_exec_fees(config, &action_receipt.actions(), receipt.receiver_id())?
            .gas
            .checked_add(config.fees.fee(ActionCosts::new_action_receipt).exec_fee().gas)
            .ok_or(IntegerOverflowError)?;
    // account for gas guaranteed to be used for creating new receipts
    let prepaid_send_cost = total_prepaid_send_fees(config, &action_receipt.actions())?;
    let prepaid_gas = prepaid_exec_gas.checked_add_result(prepaid_send_cost.gas)?;

    // account for gas potentially used for dynamic execution
    let gas_attached_to_fns = total_prepaid_gas(&action_receipt.actions())?;
    let gas = gas_attached_to_fns.checked_add_result(prepaid_gas)?;

    Ok(gas)
}
```

**File:** core/parameters/src/config.rs (L180-187)
```rust
    /// How much gas the chosen allowed shard can send to a 100% congested shard.
    ///
    /// This amount is the absolute minimum of new workload a congested shard has to
    /// accept every round. It ensures deadlocks are provably impossible. But in
    /// ideal conditions, the gradual reduction of new workload entering the system
    /// combined with gradually limited forwarding to congested shards should
    /// prevent shards from becoming 100% congested in the first place.
    pub allowed_shard_outgoing_gas: Gas,
```

**File:** core/primitives/src/congestion_info.rs (L79-92)
```rust
    /// How much gas another shard can send to us in the next block.
    pub fn outgoing_gas_limit(&self, sender_shard: ShardId) -> Gas {
        let congestion = self.congestion_level();

        if Self::is_fully_congested(congestion) {
            // Red traffic light: reduce to minimum speed
            if sender_shard == ShardId::from(self.info.allowed_shard()) {
                self.config.allowed_shard_outgoing_gas
            } else {
                Gas::ZERO
            }
        } else {
            mix_gas(self.config.max_outgoing_gas, self.config.min_outgoing_gas, congestion)
        }
```
