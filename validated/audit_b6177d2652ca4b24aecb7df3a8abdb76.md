### Title
Unvalidated Zero-Address Refund Recipient in L1→L2 Transaction Processing Permanently Burns User Refund Funds - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

### Summary
The `reserved[1]` field of ABI-encoded L1→L2 and upgrade transactions encodes the refund recipient address. This field is never validated against the zero address during transaction structure validation. When `reserved[1]` is zero, the refund amount (unused gas × gas price) is minted/transferred to `address(0)`, permanently burning the user's refund tokens with no protocol-level rejection or warning.

### Finding Description
In `basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`, the `validate_structure` function explicitly skips validation of `reserved[1]` with a developer-acknowledged `TODO`: [1](#0-0) 

All other reserved fields are validated (e.g., `reserved[2]` and `reserved[3]` must be zero, `paymaster` must be zero), but `reserved[1]` — the refund recipient — is accepted as any value including `B160::ZERO`.

Later, in `process_l1_transaction.rs`, this unvalidated value is used directly as the destination for minting the refund: [2](#0-1) 

The helper `u256_to_b160_checked` only asserts the value fits in 160 bits (upper 96 bits are zero); it does **not** check for `B160::ZERO`: [3](#0-2) 

The test suite confirms zero address is accepted and processed without error — the test `test_treasury_based_token_distribution_regression` explicitly uses `address!("0000000000000000000000000000000000000000")` as refund recipient and asserts the refund amount is credited there: [4](#0-3) 

### Impact Explanation
When `reserved[1]` is zero, the computed refund (`(gas_limit - gas_used) × gas_price`) is minted to `address(0)` and permanently lost. This is a direct, irreversible loss of user funds. The amount can be significant: with `gas_limit = 100_000`, `gas_price = 1000`, and 50% gas unused, the burned refund is `50,000,000` base token units. L1→L2 transactions cannot be invalidated once submitted, so there is no recovery path.

### Likelihood Explanation
L1→L2 transactions are submitted by users or L1 bridge contracts. Any L1 bridge implementation that defaults `refund_recipient` to `address(0)` (e.g., when the user does not specify one) would silently burn all refunds for those transactions. The `TODO: validate address?` comment confirms the developers themselves identified this as an unresolved gap. The entry path requires no privilege — any unprivileged user submitting an L1→L2 transaction with zero refund recipient triggers this path.

### Recommendation
In `validate_structure` within `basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`, replace the `TODO` comment with an explicit check:

```rust
Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
    // reserved[1] is the refund recipient; must be a valid non-zero address
    let refund_addr = u256_try_to_b160(self.reserved[1].read());
    if refund_addr.is_none() || refund_addr == Some(B160::ZERO) {
        return Err(());
    }
}
```

Alternatively, if zero address is intentionally allowed as a "burn" destination, document this explicitly and remove the `TODO`.

### Proof of Concept
1. Submit an L1→L2 transaction with `reserved[1] = U256::ZERO` (zero refund recipient).
2. The transaction passes `validate_structure` without error (the `TODO` branch is a no-op).
3. After execution, `to_refund_recipient > U256::ZERO` (there is unused gas).
4. `u256_to_b160_checked(U256::ZERO)` returns `B160::ZERO`.
5. `mint_base_token` is called with `&refund_recipient = B160::ZERO`, crediting the refund to `address(0)`.
6. The user's refund is permanently burned.

The existing test at `tests/instances/transactions/src/lib.rs:1843` already demonstrates this exact scenario succeeds without any error. [1](#0-0) [5](#0-4) [3](#0-2)

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

**File:** tests/instances/transactions/src/lib.rs (L1843-1843)
```rust
    let refund_recipient = address!("0000000000000000000000000000000000000000"); // refund recipient (zero address)
```
