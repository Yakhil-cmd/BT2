### Title
Unvalidated Zero `refund_recipient` Causes Permanent Loss of Deposited Funds on L1→L2 Transaction Revert - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

### Summary

When an L1→L2 priority transaction reverts on L2, the bootloader unconditionally sends the entire remaining deposit (`total_deposited - pay_to_operator`) to `transaction.reserved[1]` (the `refund_recipient` field). If this field is `address(0)` — which is the default when not explicitly set — the funds are permanently transferred to the zero address on L2 and are irrecoverable. The `validate_structure()` function contains a `TODO: validate address?` comment but performs no actual check.

### Finding Description

In `process_l1_transaction`, after a failed L1→L2 execution, the refund path is:

```rust
// Mint refund portion of the deposit to the refund recipient.
if to_refund_recipient > U256::ZERO {
    let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
    mint_base_token::<S, Config>(
        system,
        system_functions,
        memories.reborrow(),
        &to_refund_recipient,
        &refund_recipient,   // ← no zero-address guard
        ...
    )
``` [1](#0-0) 

`refund_recipient` is taken verbatim from `reserved[1]`. There is no fallback to `transaction.from` and no rejection of `address(0)`.

The `validate_structure()` function explicitly acknowledges the gap:

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?
    }
``` [2](#0-1) 

The `ZKsyncL1Tx` struct documents `refund_recipient` as: *"If the transaction fails, then this address will receive the `value` of this transaction."* Its default is `Address::default()` = `address(0)`. [3](#0-2) 

The `L1TxBuilder` defaults `refund_recipient` to `address(0)` when not explicitly set: [4](#0-3) 

When the L2 execution reverts, the full deposit minus the operator fee is computed as `to_refund_recipient`: [5](#0-4) 

This amount is then minted to `address(0)` with no guard, permanently burning it.

### Impact Explanation

**High.** Any L1→L2 transaction that:
1. Does not explicitly set `refund_recipient` (defaults to `address(0)`), AND
2. Reverts on L2 (e.g., target contract reverts, out-of-gas, invalid calldata)

will have its entire deposited base token (minus operator fee) permanently sent to `address(0)` on L2. These tokens are unrecoverable. The deposit was locked on L1 and the corresponding L2 tokens are burned. The user loses the full `total_deposited - gas_used * gas_price` amount.

### Likelihood Explanation

**Medium.** L1 bridge contracts, automated relayers, and users interacting with ZKsync OS via the L1 contract interface frequently omit `refund_recipient` or set it to `address(0)` as a placeholder. The existing test suite itself uses `address(0)` as the refund recipient in the treasury regression test: [6](#0-5) 

Any L1→L2 transaction that reverts — due to a contract revert, insufficient gas for the L2 call body, or any other reason — triggers the loss. Reverts on L2 are a normal operational occurrence.

### Recommendation

1. In `validate_structure()`, reject L1 and upgrade transactions where `reserved[1]` is `address(0)`. Remove the `TODO: validate address?` comment and replace it with an actual check:

```rust
Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
    let refund_addr = self.reserved[1].read();
    if refund_addr.is_zero() {
        return Err(());
    }
}
```

2. Alternatively, in `process_l1_transaction`, fall back to `transaction.from` when `reserved[1]` is zero:

```rust
let refund_recipient = {
    let r = u256_to_b160_checked(transaction.reserved[1].read());
    if r == B160::ZERO { transaction.from.read() } else { r }
};
``` [7](#0-6) 

### Proof of Concept

1. Submit an L1→L2 transaction with `refund_recipient = address(0)` (the default), `to_mint = 1 ETH`, `gas_limit = 100_000`, `gas_price = 1000`, targeting a contract that always reverts.
2. On L2, the transaction reverts. `is_success = false`.
3. `to_refund_recipient = total_deposited - pay_to_operator = 1 ETH - (gas_used * 1000)`.
4. `refund_recipient = u256_to_b160_checked(reserved[1]) = address(0)`.
5. `mint_base_token(..., &to_refund_recipient, &address(0), ...)` is called.
6. `transfer_from_treasury` subtracts from the treasury and adds to `address(0)`.
7. The user's deposited funds (minus operator fee) are permanently at `address(0)` on L2 with no recovery path. [8](#0-7)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L311-360)
```rust
    // Refund
    let to_refund_recipient = if !is_success {
        // Upgrade transactions must always succeed
        if !is_priority_op {
            return Err(internal_error!("Upgrade transaction must succeed").into());
        }
        // If the transaction reverts, then the minting of the deposit
        // reverted too. Thus, we need to refund the entire deposit minus
        // the fee (`pay_to_operator`).
        total_deposited
            .checked_sub(pay_to_operator)
            .ok_or(internal_error!("td-pto"))
    } else {
        // If the transaction succeeds, then it is assumed that the
        // mint to `from` address was transferred correctly too.
        // In this case, we just refund the unused gas that the
        // transaction paid for initially.
        let prepaid_fee = gas_price
            .checked_mul(U256::from(transaction.gas_limit.read()))
            .ok_or(internal_error!("gp*gl"))?;
        prepaid_fee
            .checked_sub(pay_to_operator)
            .ok_or(internal_error!("pf-pto"))
    }?;
    // Mint refund portion of the deposit to the refund recipient.
    if to_refund_recipient > U256::ZERO {
        let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
        mint_base_token::<S, Config>(
            system,
            system_functions,
            memories.reborrow(),
            &to_refund_recipient,
            &refund_recipient,
            l1_chain_id,
            &mut inf_resources,
            tracer,
            validator,
        )
        .map_err(|e| -> BootloaderSubsystemError {
            match e.root_cause() {
                RootCause::Runtime(RuntimeError::OutOfErgs(_)) => {
                    internal_error!("Out of ergs on infinite ergs").into()
                }
                RootCause::Runtime(RuntimeError::FatalRuntimeError(_)) => {
                    internal_error!("Out of native on infinite").into()
                }
                _ => e,
            }
        })?;
    }
```

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs (L267-273)
```rust
        // reserved[1] = refund recipient for l1 to l2 and upgrade txs
        match tx_type {
            Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
                // TODO: validate address?
            }
            _ => unreachable!(),
        }
```

**File:** tests/common/src/zksync_tx/l1_tx.rs (L25-27)
```rust
    /// The recipient of the refund for the transaction on L2. If the transaction fails, then this
    /// address will receive the `value` of this transaction.
    pub refund_recipient: Address,
```

**File:** tests/rig/src/utils/mod.rs (L408-410)
```rust
            nonce: self.nonce,
            refund_recipient: self.refund_recipient.unwrap_or_default(),
            factory_deps: self.factory_deps,
```

**File:** tests/instances/transactions/src/lib.rs (L1843-1843)
```rust
    let refund_recipient = address!("0000000000000000000000000000000000000000"); // refund recipient (zero address)
```
