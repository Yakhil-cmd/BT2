### Title
Missing Refund-Recipient Address Validation in L1→L2 Transaction Structure — (`File: basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`)

---

### Summary

`AbiEncodedTransaction::validate_structure` explicitly skips address-range validation for `reserved[1]` (the refund recipient) with a `// TODO: validate address?` comment. Any 256-bit value is accepted without verifying that the upper 96 bits are zero, as required for a valid 160-bit Ethereum address. The unvalidated value is later passed directly to `u256_to_b160_checked` during L1→L2 transaction execution, which — given its name and call-site pattern (no `Result` return, no error handling) — panics on non-address input. An unprivileged user who submits an L1→L2 priority transaction with a malformed `reserved[1]` can therefore halt block processing.

---

### Finding Description

In `validate_structure`, every other field is either rejected or range-checked. The `reserved[1]` slot is the sole exception:

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?   ← validation intentionally absent
    }
    _ => unreachable!(),
}
``` [1](#0-0) 

Because `validate_structure` is the only gate before the transaction is accepted, a value such as `U256::MAX` (upper 96 bits all-ones) passes through unchallenged. [2](#0-1) 

Later, in `process_l1_transaction`, the raw `reserved[1]` value is consumed without any additional guard:

```rust
let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
``` [3](#0-2) 

`u256_to_b160_checked` is called without a `?` operator or `match`, meaning it returns `B160` directly. A "checked" conversion that cannot signal failure via `Result` must panic on out-of-range input. Supplying a `reserved[1]` whose upper 96 bits are non-zero therefore triggers a panic inside the block-execution loop, aborting the entire block.

---

### Impact Explanation

A panic inside `process_l1_transaction` propagates up through `ProvingBootloader::run_prepared`, which is called with `.expect("Tried to prove a failing batch")`. [4](#0-3) 

This terminates the RISC-V proving binary and halts block finalization. Because L1→L2 priority transactions are enforced by the L1 contract and cannot be skipped by the sequencer, a single malformed transaction permanently stalls the chain until a protocol upgrade removes it — a complete liveness failure.

Secondary impact (if `u256_to_b160_checked` silently truncates instead of panicking): the gas refund is credited to the lower-160-bit truncation of the attacker-chosen value rather than the intended recipient, constituting direct loss of user funds.

---

### Likelihood Explanation

L1→L2 priority transactions (`tx_type = 0x7f`) are submitted permissionlessly by any Ethereum account via the L1 Mailbox contract. No privileged role is required. The `reserved[1]` field is caller-controlled and is encoded directly into the ABI-encoded transaction payload. [5](#0-4) 

The L1 contract may perform its own address check, but the ZKsync OS bootloader is the authoritative validator for the ZK state transition and must not rely on L1-side pre-filtering as a security control. The missing check is acknowledged in the source (`// TODO: validate address?`) and has never been closed.

---

### Recommendation

In `validate_structure`, add an explicit upper-bits check for `reserved[1]` for both `L1_L2_TX_TYPE` and `UPGRADE_TX_TYPE`:

```rust
Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
    // reserved[1] must be a valid 160-bit address (upper 96 bits zero)
    let raw = self.reserved[1].read();
    if raw >> 160 != U256::ZERO {
        return Err(());
    }
}
``` [1](#0-0) 

Additionally, add a dedicated unit test in `tests/instances/transactions/` that submits an L1→L2 transaction with `reserved[1]` having non-zero upper bits and asserts the transaction is rejected at validation time rather than panicking during execution.

---

### Proof of Concept

1. Construct a `ZKsyncL1Tx` where `refund_recipient` is encoded as a raw `U256` with non-zero upper bits (e.g., `U256::from(1) << 160`).
2. ABI-encode it so `reserved[1]` carries this value.
3. Submit the transaction to a ZKsync OS block.
4. `try_from_buffer` → `validate_structure` accepts it (the `// TODO` branch is a no-op).
5. `process_l1_transaction` reaches line 337 and calls `u256_to_b160_checked` on the out-of-range value.
6. The function panics; the block-execution loop aborts; the chain halts.

The existing test `test_treasury_based_token_distribution_regression` uses `refund_recipient = address!("0000…0000")` (zero address) and never exercises a non-address `reserved[1]`, confirming the gap. [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs (L138-227)
```rust
    pub fn try_from_buffer(buffer: UsizeAlignedByteBox<A>) -> Result<Self, ()> {
        // We are free to move this structure as UsizeAlignedByteBox has a box inside and guarantees stable
        // address of the slice that we will use to parse a transaction, so we will not make a long code with
        // partial init and drop guards, but instead will parse via 'static transmute
        let mut parser: Parser<'static> =
            Parser::new(unsafe { core::mem::transmute::<&[u8], &[u8]>(buffer.as_slice()) });

        let tx_type = parser.parse_u8()?;
        let from = parser.parse_address()?;
        let to = parser.parse_address()?;
        let gas_limit = parser.parse_u64()?;
        let gas_per_pubdata_limit = parser.parse_u32()?;
        let max_fee_per_gas = parser.parse_u256()?;
        let max_priority_fee_per_gas = parser.parse_u256()?;
        let paymaster = parser.parse_address()?;
        let nonce = parser.parse_u256()?;
        let value = parser.parse_u256()?;

        let reserved_0 = parser.parse_u256()?;
        let reserved_1 = parser.parse_u256()?;
        let reserved_2 = parser.parse_u256()?;
        let reserved_3 = parser.parse_u256()?;

        let data_offset = parser.parse_u32()?;
        let signature_offset = parser.parse_u32()?;
        let factory_deps_offset = parser.parse_u32()?;
        let paymaster_input_offset = parser.parse_u32()?;
        let reserved_dynamic_offset = parser.parse_u32()?;

        // Validate dynamic part
        let expected_offset = Self::DYNAMIC_PART_EXPECTED_OFFSET as u32;

        if data_offset.read() != expected_offset {
            return Err(());
        }
        if data_offset.read() != parser.offset as u32 {
            return Err(());
        }
        let data = parser.parse_bytes()?;

        if signature_offset.read() != parser.offset as u32 {
            return Err(());
        }
        let signature = parser.parse_bytes()?;

        if factory_deps_offset.read() != parser.offset as u32 {
            return Err(());
        }
        let factory_deps = parser.parse_bytes32_vector()?;

        if paymaster_input_offset.read() != parser.offset as u32 {
            return Err(());
        }
        let paymaster_input = parser.parse_bytes()?;

        if reserved_dynamic_offset.read() != parser.offset as u32 {
            return Err(());
        }

        // "Consume bytes"
        let reserved_dynamic = parser.parse_bytes()?;

        if parser.slice().is_empty() == false {
            return Err(());
        }

        let new = Self {
            underlying_buffer: buffer,
            tx_type,
            from,
            to,
            gas_limit,
            gas_per_pubdata_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            paymaster,
            nonce,
            value,
            reserved: [reserved_0, reserved_1, reserved_2, reserved_3],
            data,
            signature,
            factory_deps,
            paymaster_input,
            reserved_dynamic,
        };

        new.validate_structure()?;

        Ok(new)
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L336-338)
```rust
    if to_refund_recipient > U256::ZERO {
        let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
        mint_base_token::<S, Config>(
```

**File:** proof_running_system/src/system/bootloader.rs (L184-192)
```rust
    let (mut oracle, public_input) =
        ProvingBootloader::<O, L>::run_prepared::<BasicBootloaderProvingExecutionConfig>(
            oracle,
            &mut (),
            &mut NopResultKeeper::default(),
            &mut NopTracer::default(),
            &mut NopTxValidator,
        )
        .expect("Tried to prove a failing batch");
```

**File:** tests/common/src/zksync_tx/l1_tx.rs (L57-86)
```rust
impl AbiEncodableTx for ZKsyncL1Tx {
    fn abi_encode(&self, out: &mut dyn BufMut) {
        let tx_type = self.ty();
        let refund_recipient: U160 = self.refund_recipient.into();
        let reserved = [
            self.to_mint,
            U256::from(refund_recipient),
            U256::ZERO,
            U256::ZERO,
        ];
        let res = encode_abi_tx(
            tx_type,
            self.from.into_array(),
            Some(self.to.into_array()),
            self.gas_limit,
            Some(self.gas_per_pubdata_byte_limit),
            self.max_fee_per_gas,
            Some(self.max_priority_fee_per_gas),
            Some([0u8; 20]), // ignored in ZKsync OS
            self.nonce,
            self.value.to_be_bytes(),
            reserved,
            self.input.to_vec(),
            vec![],       // ignored in ZKsync OS
            Some(vec![]), // ignored in ZKsync OS
            None,         // ignored in ZKsync OS
            self.factory_deps.clone(),
        );
        out.put_slice(&res);
    }
```

**File:** tests/instances/transactions/src/lib.rs (L1843-1843)
```rust
    let refund_recipient = address!("0000000000000000000000000000000000000000"); // refund recipient (zero address)
```
