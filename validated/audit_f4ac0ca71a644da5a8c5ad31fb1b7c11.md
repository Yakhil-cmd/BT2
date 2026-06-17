### Title
Missing Zero-Address Validation for `refund_recipient` in L1→L2 Transaction Processing Causes Permanent Loss of Gas Refunds — (`basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

In `process_l1_transaction.rs`, the `reserved[1]` field of an L1→L2 (or upgrade) transaction is used directly as the refund recipient address without any zero-address check. If an L1 transaction sender sets `reserved[1] = 0`, the gas refund is minted to `address(0)`, permanently burning it. The `validate_structure()` function in `abi_encoded/mod.rs` contains an explicit `// TODO: validate address?` comment acknowledging this missing check.

---

### Finding Description

**Root cause — `validate_structure()` skips validation of `reserved[1]`:**

In `basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs` lines 267–273, the `validate_structure()` function explicitly skips validation of `reserved[1]` (the refund recipient address for L1→L2 and upgrade transactions):

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?
    }
    _ => unreachable!(),
}
```

No check is performed to ensure `reserved[1]` is a valid non-zero address.

**Propagation — `process_l1_transaction.rs` uses the unvalidated address directly:**

In `process_l1_transaction.rs` lines 336–360, after computing the refund amount, the code reads `reserved[1]` and immediately passes it to `mint_base_token`:

```rust
if to_refund_recipient > U256::ZERO {
    let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
    mint_base_token::<S, Config>(
        system,
        system_functions,
        memories.reborrow(),
        &to_refund_recipient,
        &refund_recipient,   // ← could be B160::ZERO
        ...
    )?;
}
```

The `u256_to_b160_checked` helper (`zk_ee/src/utils/integer_utils.rs` lines 132–143) only asserts that the value fits in 160 bits — it does **not** check for zero:

```rust
pub fn u256_to_b160_checked(src: U256) -> B160 {
    assert!(src.as_limbs()[3] == 0 && src.as_limbs()[2] < (1u64 << 32));
    // returns B160::ZERO when src == 0
    ...
}
```

The guard `if to_refund_recipient > U256::ZERO` only checks that the **amount** is non-zero, not that the **recipient address** is non-zero. When both conditions hold simultaneously — a non-zero refund amount and a zero recipient address — `mint_base_token` is called with `to = B160::ZERO`, crediting `address(0)` and permanently destroying the tokens.

---

### Impact Explanation

Any L1→L2 transaction (type `0x7f`) or upgrade transaction (type `0x7e`) that carries a non-zero `to_mint` deposit and sets `reserved[1] = 0` will have its entire gas refund (unused gas × gas price) permanently burned to `address(0)`. The treasury balance is debited, the tokens are credited to the zero address, and the sender receives nothing. This is an irreversible loss of base-token funds.

---

### Likelihood Explanation

The `reserved[1]` field is fully attacker/user-controlled in the L1 transaction encoding. A sender can set it to zero either:
- Deliberately (to grief themselves or test behavior),
- Accidentally (a smart contract bridge that omits the field, defaulting it to zero), or
- Via a semantic mismatch: the ZKsync Era L1 contracts historically substitute `from` for a zero `refund_recipient` before encoding, but ZKsync OS does not implement this fallback, so any path that passes zero through the L1 encoding will trigger the burn.

The `// TODO: validate address?` comment in `validate_structure()` is direct in-code evidence that the developers identified this gap and left it unresolved.

---

### Recommendation

1. **In `validate_structure()`** (`basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`, lines 267–273): reject transactions where `reserved[1]` is zero for `L1_L2_TX_TYPE` and `UPGRADE_TX_TYPE`:

```rust
Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
    if self.reserved[1].read().is_zero() {
        return Err(());
    }
}
```

2. **Alternatively, in `process_l1_transaction.rs`** (line 337): fall back to `from` when `reserved[1]` is zero, matching the L1 contract semantics:

```rust
let refund_recipient = {
    let raw = transaction.reserved[1].read();
    if raw.is_zero() { from } else { u256_to_b160_checked(raw) }
};
```

3. **Defense-in-depth**: add a zero-address guard in `transfer_from_treasury` / `mint_base_token` to reject `to = B160::ZERO` unconditionally.

---

### Proof of Concept

1. Craft an L1→L2 transaction with:
   - `to_mint` (i.e., `reserved[0]`) = `gas_limit × gas_price + 1_000_000` (non-zero deposit)
   - `refund_recipient` (i.e., `reserved[1]`) = `0x0000...0000`
   - `gas_limit` large enough that unused gas × gas_price > 0 after execution

2. Submit the transaction. The main body executes successfully.

3. Post-execution, `to_refund_recipient = prepaid_fee - pay_to_operator > 0`.

4. `u256_to_b160_checked(0)` returns `B160::ZERO`.

5. `mint_base_token(..., &to_refund_recipient, &B160::ZERO, ...)` is called.

6. `transfer_from_treasury` debits the treasury and credits `address(0)` — the refund is permanently burned.

The existing regression test at `tests/instances/transactions/src/lib.rs` line 1843 already demonstrates this exact scenario (zero refund recipient) and confirms the tokens are credited to `address(0)` without any error or revert. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L335-360)
```rust
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

**File:** zk_ee/src/utils/integer_utils.rs (L132-143)
```rust
#[inline(always)]
pub fn u256_to_b160_checked(src: U256) -> B160 {
    assert!(src.as_limbs()[3] == 0 && src.as_limbs()[2] < (1u64 << 32));
    let mut result = B160::ZERO;
    unsafe {
        result.as_limbs_mut()[0] = src.as_limbs()[0];
        result.as_limbs_mut()[1] = src.as_limbs()[1];
        result.as_limbs_mut()[2] = src.as_limbs()[2];
    }

    result
}
```
