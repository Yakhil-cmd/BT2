[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** stackslib/src/chainstate/burn/operations/transfer_stx.rs (L52-91)
```rust
    fn parse_data(data: &[u8]) -> Option<ParsedData> {
        /*
            Wire format:
            0      2  3                             19        80
            |------|--|-----------------------------|---------|
             magic  op     uSTX to transfer (u128)     memo (up to 61 bytes)

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped

             The values ustx to transfer are in big-endian order.
        */

        if data.len() < 16 {
            // too short
            warn!(
                "TransferStxOp payload is malformed ({} bytes, expected >= {})",
                data.len(),
                16
            );
            return None;
        }

        if data.len() > (61 + 16) {
            // too long
            warn!(
                "TransferStxOp payload is malformed ({} bytes, expected <= {})",
                data.len(),
                16 + 61
            );
            return None;
        }

        let transfered_ustx = parse_u128_from_be(data.get(0..16)?).unwrap();
        let memo = Vec::from(data.get(16..)?);

        Some(ParsedData {
            transfered_ustx,
            memo,
        })
    }
```

**File:** stackslib/src/chainstate/burn/operations/transfer_stx.rs (L93-110)
```rust
    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!(
                        "Invalid tx: TransferStxOp must spend the second output of the PreStacksOp"
                    );
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: TransferStxOp must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }
```

**File:** stackslib/src/chainstate/burn/operations/transfer_stx.rs (L112-195)
```rust
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<TransferStxOp, op_error> {
        TransferStxOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            tx,
            sender,
        )
    }

    /// parse a TransferStxOp
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<TransferStxOp, op_error> {
        // can't be too careful...
        let num_outputs = tx.num_recipients();

        if tx.num_signers() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if num_outputs == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::TransferStx as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = TransferStxOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        let outputs = tx.get_recipients();
        assert!(!outputs.is_empty());

        let output = outputs
            .get(0)
            .ok_or_else(|| {
                warn!("Invalid tx: No first output");
                op_error::InvalidInput
            })?
            .as_ref()
            .ok_or_else(|| {
                warn!("Invalid tx: could not decode the first output");
                op_error::InvalidInput
            })?
            .address
            .clone()
            .try_into_stacks_address()
            .ok_or_else(|| {
                warn!("Invalid tx: output must be representable as a StacksAddress");
                op_error::InvalidInput
            })?;

        Ok(TransferStxOp {
            sender: sender.clone(),
            recipient: output,
            transfered_ustx: data.transfered_ustx,
            memo: data.memo,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
```

**File:** stackslib/src/chainstate/burn/operations/transfer_stx.rs (L216-228)
```rust
impl TransferStxOp {
    pub fn check(&self) -> Result<(), op_error> {
        if self.transfered_ustx == 0 {
            warn!("Invalid TransferStxOp, must have positive ustx");
            return Err(op_error::TransferStxMustBePositive);
        }
        if self.sender == self.recipient {
            warn!("Invalid TransferStxOp, sender is recipient");
            return Err(op_error::TransferStxSelfSend);
        }
        Ok(())
    }
}
```
