### Title
L1→L2 Transaction Sender Can Set `gas_per_pubdata_limit = 0` to Avoid Paying for Pubdata — (`basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

In `process_l1_transaction`, the user-controlled `gas_per_pubdata_limit` field of L1→L2 (priority) transactions is consumed directly without any minimum-value enforcement inside ZKsync OS. Setting it to `0` collapses `native_per_pubdata` to `0`, making all pubdata effectively free for that transaction. The protocol must still publish the pubdata to the settlement layer, so the cost is absorbed by the protocol rather than the sender.

---

### Finding Description

`gas_per_pubdata_limit` is a `u32` field in the ABI-encoded L1→L2 transaction format. It is read verbatim and forwarded into the resource-accounting pipeline:

```rust
// process_l1_transaction.rs line 80
let gas_per_pubdata = transaction.gas_per_pubdata_limit.read();
``` [1](#0-0) 

It is then passed to `prepare_and_check_resources`, which computes:

```rust
// lines 481-488
let native_per_pubdata = (gas_per_pubdata as u64)
    .checked_mul(native_per_gas)
    .unwrap_or_else(|| { u64::MAX });
``` [2](#0-1) 

When `gas_per_pubdata = 0`, `native_per_pubdata = 0`. This propagates through the entire resource pipeline:

**Step 1 — `create_resources_for_tx`**: the intrinsic pubdata overhead is `native_per_pubdata * intrinsic_pubdata = 0`, so the native limit is not reduced at all. [3](#0-2) 

**Step 2 — `check_enough_resources_for_pubdata` / `get_resources_to_charge_for_pubdata`**: the native charge for pubdata is `pubdata_bytes * 0 = 0`, so the check always passes and the user is charged nothing for pubdata. [4](#0-3) 

The code comment in `prepare_and_check_resources` explicitly acknowledges that `gas_per_pubdata` is expected to be validated externally:

> *"Note that the 'validation errors' are practically unreachable, as gas_limit, gas_price and gas_per_pubdata are either checked or set by the L1 contracts."* [5](#0-4) 

However, ZKsync OS itself applies **no minimum bound** on `gas_per_pubdata_limit`. The fallback behavior when the field is `0` is not a safe default (e.g., a protocol minimum); it silently makes pubdata free. This is structurally identical to the GoGoPool `duration` bug: a user-controlled numeric field with no lower-bound enforcement in the processing layer, whose extreme value (0) minimises the cost the user is supposed to bear.

The `gas_per_pubdata_limit` field is typed as `u32` in the transaction struct: [6](#0-5) 

and documented as a user-supplied maximum: [7](#0-6) 

---

### Impact Explanation

An L1→L2 transaction sender who sets `gas_per_pubdata_limit = 0` pays **zero** for any pubdata their transaction generates. The protocol must still publish that pubdata to the settlement layer (state diffs, preimages), so the cost is borne by the protocol/operator rather than the sender. For transactions that write significant storage (e.g., contract deployments or storage-heavy calls), this represents a direct, quantifiable loss of funds to the protocol proportional to the pubdata produced.

---

### Likelihood Explanation

L1 contracts are supposed to enforce a minimum `gas_per_pubdata` before a priority transaction enters the priority queue. However:

1. ZKsync OS itself contains **no enforcement**; the code explicitly treats this as an external invariant.
2. If the L1 contracts are upgraded, misconfigured, or contain a bug that allows `gas_per_pubdata_limit = 0`, ZKsync OS will silently process the transaction with free pubdata.
3. The attacker-controlled entry path is direct: craft an L1→L2 transaction with `gas_per_pubdata_limit = 0` and submit it to the L1 priority queue.

The likelihood is **medium**: it requires either a gap in L1 contract validation or a future upgrade that relaxes the check, but the ZKsync OS layer provides no defence-in-depth.

---

### Recommendation

Add an explicit minimum-value check for `gas_per_pubdata_limit` inside `prepare_and_check_resources` (or at the top of `process_l1_transaction`). If the value is below a protocol-defined minimum (e.g., `1`), either saturate to the minimum or emit a system log and use the minimum, consistent with the existing `L1ResourcesPolicy` pattern for other arithmetic edge cases. This mirrors the GoGoPool mitigation of bounding `duration` to `[14 days, 365 days]`.

---

### Proof of Concept

1. Construct an ABI-encoded L1→L2 transaction with `gas_per_pubdata_limit = 0` and a non-trivial calldata payload that writes storage (generating pubdata).
2. Submit it to the L1 priority queue with a sufficient `max_fee_per_gas` and `value` deposit to cover gas but not pubdata.
3. Observe in ZKsync OS that `native_per_pubdata = 0`, `intrinsic_pubdata_overhead = 0`, and `check_enough_resources_for_pubdata` returns success with zero native charged for pubdata.
4. The transaction executes successfully; the sender pays only for gas, not for the pubdata bytes published to L1.

The existing test `test_l1_tx_not_enough_native_for_pubdata_burns_all_gas` (which uses `gas_per_pubdata_byte_limit = 1_500`) demonstrates the pubdata-charging path; running the same test with `gas_per_pubdata_byte_limit = 0` would show the transaction succeeds without any pubdata charge. [8](#0-7)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L77-80)
```rust
    // For L1->L2 transactions we always use the pubdata price provided by the transaction.
    // This is needed to ensure DDoS protection. All the excess expenditure
    // will be refunded to the user.
    let gas_per_pubdata = transaction.gas_per_pubdata_limit.read();
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L422-433)
```rust
///
/// Compute and perform some checks on fee/resource parameters.
/// This function handles cases that for L2 transactions would be
/// validation errors, as "invalidating" an L1 transaction can halt
/// the chain (due to the priority queue).
/// Note that the "validation errors" are practically unreachable, as
/// gas_limit, gas_price and gas_per_pubdata are either checked or set
/// by the L1 contracts. We decide to handle these cases as a fallback in
/// case the L1 contracts aren't properly updated to reflect a change in
/// ZKsync OS.
/// The approach is to use saturating arithmetic and emit a system
/// log if this situation ever happens.
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L481-488)
```rust
    let native_per_pubdata = (gas_per_pubdata as u64)
        .checked_mul(native_per_gas)
        .unwrap_or_else(|| {
            system_log!(
                system,
                "Native per pubdata calculation for L1 tx overflows, using saturated arithmetic instead");
                u64::MAX
        });
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L351-359)
```rust
    // Charge intrinsic pubdata
    let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
    let native_limit = match native_limit.checked_sub(intrinsic_pubdata_overhead) {
        Some(val) => val,
        None => P::handle_arithmetic_error(
            system,
            P::native_underflow_error("subtracting pubdata overhead"),
        )?,
    };
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L430-434)
```rust
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
    let native = <S::Resources as zk_ee::system::Resources>::Native::from_computational(native);
    Ok((current_pubdata_spent, S::Resources::from_native(native)))
```

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs (L49-51)
```rust
    /// The maximum amount of gas the user is willing to pay for a byte of pubdata.
    #[allow(dead_code)]
    pub gas_per_pubdata_limit: ParsedValue<u32>,
```

**File:** docs/bootloader/transaction_format.md (L16-16)
```markdown
| `gas_per_pubdata_limit`   | `u32`        | Maximum gas the user is willing to pay for a byte of [pubdata](https://docs.zksync.io/zksync-protocol/contracts/handling-pubdata).                                                                                               |
```

**File:** tests/instances/transactions/src/native_charging.rs (L249-291)
```rust
    let make_tx = |gas_per_pubdata_byte_limit| {
        let tx: ZKsyncTxEnvelope = L1TxBuilder::new()
            .from(from)
            .to(TO)
            .gas_price(1000)
            .gas_limit(gas_limit.into())
            .gas_per_pubdata_byte_limit(gas_per_pubdata_byte_limit)
            .build()
            .into();
        tx
    };

    // Control execution should succeed, so the failing case below is specific to
    // charging for execution pubdata.
    let mut control_tester = TestingFramework::new()
        .with_evm_contract(TO, &bytecode)
        .with_balance(from, U256::from(1_000_000_000_000_000_u64));
    let control_output = control_tester.execute_block(vec![make_tx(1)]);
    let control_tx = control_output.tx_results[0]
        .as_ref()
        .expect("Control tx should be processed");
    assert!(
        control_tx.is_success(),
        "Control tx must succeed with a low pubdata price"
    );

    let mut tester = TestingFramework::new()
        .with_evm_contract(TO, &bytecode)
        .with_balance(from, U256::from(1_000_000_000_000_000_u64));
    let output = tester.execute_block(vec![make_tx(1_500)]);
    let tx_result = output.tx_results[0]
        .as_ref()
        .expect("Tx should be processed even when reverted");

    assert!(
        !tx_result.is_success(),
        "Tx should revert when L1 pubdata charging exceeds the remaining native budget"
    );
    assert_eq!(
        tx_result.gas_used, gas_limit,
        "L1 tx reverted by post-execution pubdata charging must consume full gas limit"
    );
}
```
