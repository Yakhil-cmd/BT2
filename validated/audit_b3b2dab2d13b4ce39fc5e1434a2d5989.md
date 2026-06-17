### Title
`gas_per_pubdata_limit` Parsed as `u32` While Solidity ABI Defines It as `uint256`, Causing L1→L2 Transaction Rejection and Permanent Fund Loss - (`File: basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`)

---

### Summary

The `gas_per_pubdata_limit` field of ABI-encoded L1→L2 transactions is parsed with a `u32` type constraint in ZKsync OS, while the canonical Solidity `Transaction` struct defines `gasPerPubdataByteLimit` as `uint256`. Any L1→L2 transaction submitted with `gas_per_pubdata_byte_limit > u32::MAX` (4,294,967,295) will fail to parse and be rejected with `InvalidEncoding`, potentially causing permanent loss of deposited funds.

---

### Finding Description

In `AbiEncodedTransaction::try_from_buffer`, the fifth field of the ABI-encoded transaction is parsed using `parse_u32()`:

```rust
let gas_per_pubdata_limit = parser.parse_u32()?;
``` [1](#0-0) 

The `parse_u32()` method calls `validate_u32()`, which enforces that the upper 28 bytes of the 32-byte ABI word are zero:

```rust
pub fn validate_u32(&self) -> Result<u32, ()> {
    for byte in 0..28 {
        if self.encoding[byte] != 0 {
            return Err(());
        }
    }
    ...
}
``` [2](#0-1) 

Any value exceeding `u32::MAX` causes `validate_u32()` to return `Err(())`, which propagates up through `try_from_buffer` as `Err(())`, and is then mapped to `TxError::Validation(InvalidTransaction::InvalidEncoding)`:

```rust
TxEncodingFormat::Abi => {
    let tx = AbiEncodedTransaction::try_from_buffer(buffer)
        .map_err(|_| TxError::Validation(InvalidTransaction::InvalidEncoding))?;
    Ok(Self::Abi(tx))
}
``` [3](#0-2) 

However, the canonical Solidity `Transaction` struct (as seen in the ABI artifacts) defines `gasPerPubdataByteLimit` as `uint256`: [4](#0-3) 

The L1 transaction test helper also uses `u128` for this field, confirming the L1 contract accepts values far beyond `u32::MAX`: [5](#0-4) 

The ZKsync OS internal documentation acknowledges the `u32` type for this field, but this is inconsistent with the on-chain Solidity ABI: [6](#0-5) 

The field is subsequently used in resource calculations as `u64` (widened from `u32`), confirming there is no semantic reason for the `u32` constraint — it is purely a parsing artifact: [7](#0-6) 

---

### Impact Explanation

An L1→L2 transaction submitted with `gas_per_pubdata_byte_limit > 4,294,967,295` (e.g., set to `type(uint256).max` as a common "unlimited" sentinel, or any value in the `u64`/`u128`/`u256` range) will be rejected by ZKsync OS with `InvalidEncoding` at the parsing stage. Since L1→L2 transactions carry deposited ETH or tokens from L1, and failed L1→L2 transactions cannot be retried, this results in permanent loss of deposited funds for the affected user.

---

### Likelihood Explanation

The L1 bridge contract accepts `uint256` for `gasPerPubdataByteLimit` with no upper-bound validation. Users or smart contracts that set this field to `type(uint256).max` (a common pattern for "accept any price") or any value above `u32::MAX` will trigger the rejection. This is a realistic user action, particularly for automated bridge integrations that use max-value sentinels.

---

### Recommendation

Change the parsing of `gas_per_pubdata_limit` from `parse_u32()` to `parse_u64()` (or `parse_u128()`) to match the range accepted by the L1 Solidity contract. Update the `gas_per_pubdata_limit` field type in `AbiEncodedTransaction` from `ParsedValue<u32>` to `ParsedValue<u64>`. The downstream usage at `(gas_per_pubdata as u64)` already widens to `u64`, so this change is backward-compatible. [8](#0-7) [1](#0-0) 

---

### Proof of Concept

1. Construct an L1→L2 transaction (type `0x7f`) with `gas_per_pubdata_byte_limit = 0x100000000` (i.e., `u32::MAX + 1 = 4,294,967,296`). This is a valid `uint256` value accepted by the L1 bridge contract.
2. Submit the transaction to ZKsync OS.
3. `AbiEncodedTransaction::try_from_buffer` calls `parser.parse_u32()` for the `gas_per_pubdata_limit` field.
4. `validate_u32()` finds byte 27 of the 32-byte word is non-zero (`0x01`), returns `Err(())`.
5. `try_from_buffer` returns `Err(())`, mapped to `TxError::Validation(InvalidTransaction::InvalidEncoding)`.
6. The transaction is rejected. Any ETH or tokens deposited on L1 for this transaction are permanently locked.

### Citations

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs (L51-51)
```rust
    pub gas_per_pubdata_limit: ParsedValue<u32>,
```

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs (L149-149)
```rust
        let gas_per_pubdata_limit = parser.parse_u32()?;
```

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/u256be_ptr.rs (L64-72)
```rust
    pub fn validate_u32(&self) -> Result<u32, ()> {
        for byte in 0..28 {
            if self.encoding[byte] != 0 {
                return Err(());
            }
        }
        let value = u32::from_be_bytes(self.encoding[28..32].try_into().unwrap());
        Ok(value)
    }
```

**File:** basic_bootloader/src/bootloader/transaction/mod.rs (L87-91)
```rust
            TxEncodingFormat::Abi => {
                let tx = AbiEncodedTransaction::try_from_buffer(buffer)
                    .map_err(|_| TxError::Validation(InvalidTransaction::InvalidEncoding))?;
                Ok(Self::Abi(tx))
            }
```

**File:** tests/contracts_sol/c_aa/out/DefaultAccount.abi.json (L450-455)
```json
                    {
                        "internalType": "uint256",
                        "name": "gasPerPubdataByteLimit",
                        "type": "uint256"
                    },
                    {
```

**File:** tests/common/src/zksync_tx/l1_tx.rs (L18-18)
```rust
    pub gas_per_pubdata_byte_limit: u128,
```

**File:** docs/bootloader/transaction_format.md (L16-16)
```markdown
| `gas_per_pubdata_limit`   | `u32`        | Maximum gas the user is willing to pay for a byte of [pubdata](https://docs.zksync.io/zksync-protocol/contracts/handling-pubdata).                                                                                               |
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
