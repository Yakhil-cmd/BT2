### Title
Unvalidated `refund_recipient` in L1→L2 Transactions Allows Permanent Loss of Deposited Tokens - (`basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`, `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

L1→L2 priority transactions carry a `refund_recipient` address in `reserved[1]`. ZKsync OS explicitly skips validation of this field (marked `// TODO: validate address?`). When a transaction fails (reverts), the entire deposit minus the operator fee is minted to whatever address is in `reserved[1]`. If that address is `address(0)` — the default when no recipient is set — the tokens are permanently burned with no recovery path.

---

### Finding Description

The `validate_structure` function for ABI-encoded L1 transactions parses `reserved[1]` as the refund recipient but performs no validation on it:

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?
    }
    _ => unreachable!(),
}
``` [1](#0-0) 

Later, in `process_l1_transaction`, when the transaction fails, the full deposit minus operator fee is unconditionally minted to whatever `reserved[1]` contains — including `B160::ZERO`:

```rust
if to_refund_recipient > U256::ZERO {
    let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
    mint_base_token::<S, Config>(
        system, system_functions, memories.reborrow(),
        &to_refund_recipient,
        &refund_recipient,   // ← can be address(0), no check
        ...
    )?;
}
``` [2](#0-1) 

`mint_base_token` calls `transfer_from_treasury`, which subtracts from the treasury and adds to `to` — with no guard against `to == B160::ZERO`: [3](#0-2) 

The `L1TxBuilder` helper defaults `refund_recipient` to `Address::default()` (i.e., `address(0)`) when not explicitly set: [4](#0-3) 

A regression test explicitly uses `address(0)` as refund recipient and verifies tokens flow there, confirming ZKsync OS does not substitute `address(0)` with the sender: [5](#0-4) 

---

### Impact Explanation

**Vulnerability type**: Public funds-loss path / resource accounting bug.

When an L1→L2 transaction reverts (e.g., the target contract reverts, or the transaction runs out of gas for pubdata), the bootloader computes `to_refund_recipient = total_deposited - pay_to_operator` and mints that amount to `reserved[1]`. If `reserved[1]` is `address(0)`, the tokens are credited to the zero address — an address no one controls — and are permanently irrecoverable. There is no rescue or recovery function anywhere in ZKsync OS that can retrieve tokens from `address(0)`.

The amount at risk equals `total_deposited - gas_used * gas_price`, which for a failed high-value deposit can be the majority of the bridged amount.

**Impact**: High — direct, permanent loss of user funds with no recovery path.

---

### Likelihood Explanation

Two realistic paths lead to this state:

1. **User omission**: A user or dApp submits an L1→L2 transaction without explicitly setting `refund_recipient`. The default is `address(0)`. If the L2 call reverts, the deposit is burned.

2. **L1 contract gap**: The ZKsync OS codebase explicitly acknowledges that L1 validation may be imperfect and tries to handle edge cases defensively. The `// TODO: validate address?` comment confirms the ZKsync OS layer itself does not close this gap. If the L1 contracts ever pass through `address(0)` (e.g., during an upgrade or misconfiguration), ZKsync OS will silently burn the refund.

The `L1TxBuilder` default and the existing test that treats `address(0)` as a valid refund recipient confirm this path is reachable today.

**Likelihood**: Medium — requires a failed L1→L2 transaction with an unset or zero refund recipient, which is a common user pattern.

---

### Recommendation

In `validate_structure`, replace the `// TODO: validate address?` comment with an actual check that rejects `reserved[1]` values that are not valid 20-byte addresses (i.e., upper 96 bits must be zero and the resulting address must be non-zero):

```rust
Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
    let recipient = self.reserved[1].read();
    // Reject if upper bits are set (not a valid address)
    if recipient.as_limbs()[3] != 0 || recipient.as_limbs()[2] >= (1u64 << 32) {
        return Err(());
    }
    // Reject address(0) as refund recipient to prevent permanent token loss
    if recipient.is_zero() {
        return Err(());
    }
}
```

Alternatively, if `address(0)` is intentionally allowed (e.g., to mean "refund to sender"), add explicit substitution logic in `process_l1_transaction` before calling `mint_base_token`:

```rust
let refund_recipient = {
    let raw = u256_to_b160_checked(transaction.reserved[1].read());
    if raw == B160::ZERO { transaction.from.read() } else { raw }
};
``` [1](#0-0) [6](#0-5) 

---

### Proof of Concept

1. Alice submits an L1→L2 priority transaction with:
   - `to_mint = 10 ETH` (total deposit)
   - `gas_limit = 100_000`, `gas_price = 1000` (max fee = 0.1 ETH)
   - `refund_recipient = address(0)` (default / not set)
   - `to` = a contract that always reverts

2. ZKsync OS processes the transaction:
   - `execute_l1_transaction_and_notify_result` runs the call → reverts → `is_success = false`
   - `pay_to_operator = gas_used * gas_price` (e.g., 0.05 ETH)
   - `to_refund_recipient = total_deposited - pay_to_operator = 9.95 ETH`

3. Since `to_refund_recipient > 0`, `mint_base_token` is called with `refund_recipient = address(0)`:
   - Treasury balance decreases by 9.95 ETH
   - `address(0)` balance increases by 9.95 ETH

4. Alice's 9.95 ETH is permanently lost. No rescue function exists in ZKsync OS to recover tokens from `address(0)`. [7](#0-6) [8](#0-7)

### Citations

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L312-360)
```rust
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L771-831)
```rust
/// Transfers [value] from the treasury account to address [to].
///
/// Returns `TreasuryTransferFailed` if:
/// - Treasury has insufficient balance
/// - Balance overflow occurs
pub fn transfer_from_treasury<'a, S: EthereumLikeTypes + 'a>(
    system: &mut System<S>,
    nominal_token_value: &U256,
    to: &B160,
    resources: &mut S::Resources,
    fee_payment_in_simulation: bool,
) -> Result<(), BootloaderSubsystemError>
where
    S::IO: IOSubsystemExt,
{
    system_log!(
        system,
        "Transferring {nominal_token_value:?} tokens from treasury to {to:?}\n"
    );

    let treasury_address = &system_hooks::addresses_constants::BASE_TOKEN_HOLDER_ADDRESS;

    let _ = system
        .io
        .update_account_nominal_token_balance(
            zk_ee::execution_environment_type::ExecutionEnvironmentType::EVM,
            resources,
            treasury_address,
            nominal_token_value,
            true, // true = subtract from balance
            fee_payment_in_simulation,
        )
        .map_err(|e| -> BootloaderSubsystemError {
            match e {
                SubsystemError::LeafUsage(balance_error) => {
                    system_log!(system, "Treasury transfer failed: {balance_error:?}");
                    interface_error!(BootloaderInterfaceError::TreasuryTransferFailed)
                }
                _ => wrap_error!(e),
            }
        })?;

    let _ = system
        .io
        .update_account_nominal_token_balance(
            zk_ee::execution_environment_type::ExecutionEnvironmentType::EVM,
            resources,
            to,
            nominal_token_value,
            false, // false = add to balance
            fee_payment_in_simulation,
        )
        .map_err(|e| -> BootloaderSubsystemError {
            match e {
                SubsystemError::LeafUsage(balance_error) => {
                    system_log!(system, "Error while minting: {balance_error:?}");
                    interface_error!(BootloaderInterfaceError::MintingBalanceOverflow)
                }
                _ => wrap_error!(e),
            }
        })?;
```

**File:** tests/rig/src/utils/mod.rs (L409-409)
```rust
            refund_recipient: self.refund_recipient.unwrap_or_default(),
```

**File:** tests/instances/transactions/src/lib.rs (L1843-1843)
```rust
    let refund_recipient = address!("0000000000000000000000000000000000000000"); // refund recipient (zero address)
```
