### Title
Attacker-controlled `PreStxOp.output` lets anyone drain a victim's unlocked STX via a follow-up `TransferStxOp` with no signature from the victim - (File: `stackslib/src/chainstate/burn/operations/transfer_stx.rs`, `stackslib/src/burnchains/burnchain.rs`)

### Summary
`PreStxOp::parse_from_tx` derives `output` purely from output[0]'s Bitcoin script, with zero cryptographic link to who signs the tx's input(s). `classify_transaction` then sets `TransferStxOp.sender = pre_stx.output` whenever a later tx spends output[1] of that `PreStxOp` tx, and `TransferStxOp::check()` performs no ownership verification of `sender`. `process_transfer_ops`/`run_stx_transfer` moves real STX balance based solely on this unauthenticated `sender` field.

### Finding Description
The broken equality: **the STX account debited by the applied `TransferStxOp` (victim's `sender` = `pre_stx.output`) must equal the STX account actually authorized by whoever signed the Bitcoin inputs of the operation chain** — but nothing in the code enforces this.

Trace:
1. `PreStxOp::parse_from_tx` builds `PreStxOp.output` strictly from output[0]'s script pubkey/address, with no check binding it to `tx.num_signers()`/input keys: [1](#0-0) . An attacker can set output[0] to the victim's `StacksAddress` while funding/controlling output[1] entirely themselves.
2. `classify_transaction` resolves a subsequent `TransferStx` opcode tx by requiring its input[0] to spend vout=1 of the `PreStxOp` tx (`TransferStxOp::get_sender_txid`), then sets `sender = &pre_stx.output` and calls `TransferStxOp::from_tx`: [2](#0-1)  and [3](#0-2) .
3. `TransferStxOp::parse_from_tx` just copies this attacker/victim-controlled `sender` into the resulting op and reads `recipient`/`transfered_ustx` from the attacker-crafted tx: [4](#0-3) .
4. `SortitionHandleTx::check_transaction` for `TransferStx` only calls `op.check()`: [5](#0-4) , and `TransferStxOp::check()` only verifies `transfered_ustx != 0` and `sender != recipient` — it never verifies that `sender` corresponds to a key the attacker actually controls: [6](#0-5) .
5. `StacksChainState::process_transfer_ops` then unconditionally calls `run_stx_transfer(&sender, &recipient, transfered_ustx, ...)` as a privileged "as_transaction" Clarity call, moving real balance with no Stacks-level signature check at all: [7](#0-6) .

Because the only "proof" required is spending output[1] of the `PreStxOp` tx — and the attacker created and funded that `PreStxOp` tx themselves — the attacker fully controls both the "authorization" (spending vout=1) and the named `sender` (victim's address in vout=0), with no linkage between the two.

### Impact Explanation
An attacker can name any existing `StacksAddress` as `sender` and drain its entire unlocked STX balance to an attacker-controlled `recipient`, using only two low-cost Bitcoin transactions that they alone sign. This is direct theft of a third party's unlocked STX with zero authorization from the victim, repeatable against any address with a positive balance, matching the Critical severity bucket for "theft of ... unbacked ... STX."

### Likelihood Explanation
Preconditions are minimal and cheap: the attacker needs to fund a `PreStxOp` Bitcoin transaction (a couple of dust/fee-level outputs) naming the victim's address in output[0] and their own key in output[1], wait for a confirmation/sortition, then submit a `TransferStxOp` spending vout=1 with `transfered_ustx` set to drain the victim's balance and `recipient` set to themselves. No PoX cycle phase, membership, or contract-call gating applies since this is a raw burnchain-op path independent of `pox-4`/`pox-5`. This is fully repeatable against every address holding unlocked STX and costs only Bitcoin transaction fees.

### Recommendation
Bind the "authorized STX principal" cryptographically to the Bitcoin signer, e.g., require that `PreStxOp.output`'s hash160 matches the hash160 of the public key that signs input 0 of the `PreStxOp` transaction (or equivalently require it to match the address controlling output[1], which is the output later spent to prove authorization), and enforce this check in `PreStxOp::parse_from_tx` before accepting the op. Alternatively, require `TransferStxOp`/`StackStxOp`/`DelegateStxOp` `sender` to be independently re-derived from the key that signs the follow-up transaction's input rather than trusting `pre_stx.output` verbatim.

### Proof of Concept
Rust integration test (style of `stackslib/src/burnchains/tests/db.rs`):
1. Build a `BitcoinTransaction` with opcode `PreStx`, output[0] = victim's legacy Bitcoin address (mapped to victim's known `StacksAddress`), output[1] = attacker's own address; insert via `BurnchainDB::store_new_burnchain_block`.
2. Build a second `BitcoinTransaction` with opcode `TransferStx`, input[0] = `(pre_stx_txid, 1)` (spending the attacker-controlled vout=1), data encoding `transfered_ustx` = victim's full known STX balance, output[0] = attacker's recipient address.
3. Run `Burnchain::classify_transaction` / `get_blockstack_transactions` and assert the resulting `TransferStxOp.sender == victim_addr` even though no input of either transaction was signed by any key associated with the victim's `StacksAddress`.
4. Feed the op through `StacksChainState::process_transfer_ops` against a chainstate where victim has a nonzero unlocked balance, and assert:
   - `victim_balance_after < victim_balance_before` (specifically decreased by `transfered_ustx`)
   - `attacker_balance_after == attacker_balance_before + transfered_ustx`
   - despite the fact that `victim` never signed any Bitcoin input in either transaction (assert on `tx.get_signers()`/input pubkeys never resolving to victim's key).

### Citations

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L106-126)
```rust
        let outputs = tx.get_recipients();
        assert!(!outputs.is_empty());

        let output = outputs
            .get(0)
            .ok_or_else(|| {
                warn!("Invalid tx: first output not found");
                op_error::InvalidInput
            })?
            .as_ref()
            .ok_or_else(|| {
                warn!("Invalid tx: first output cannot be decoded");
                op_error::InvalidInput
            })?
            .address
            .clone()
            .try_into_stacks_address()
            .ok_or_else(|| {
                warn!("Invalid tx: first output must be representable as a StacksAddress");
                op_error::InvalidInput
            })?;
```

**File:** stackslib/src/burnchains/burnchain.rs (L900-919)
```rust
            x if x == Opcodes::TransferStx as u8 => {
                let pre_stx_txid = TransferStxOp::get_sender_txid(burn_tx).ok()?;
                let pre_stx_tx = match pre_stx_op_map.get(pre_stx_txid) {
                    Some(tx_ref) => Some(BlockstackOperationType::PreStx(tx_ref.clone())),
                    None => burnchain_db.find_burnchain_op(indexer, pre_stx_txid),
                };
                if let Some(BlockstackOperationType::PreStx(pre_stx)) = pre_stx_tx {
                    let sender = &pre_stx.output;
                    match TransferStxOp::from_tx(block_header, burn_tx, sender) {
                        Ok(op) => Some(BlockstackOperationType::TransferStx(op)),
                        Err(e) => {
                            warn!(
                                "Failed to parse transfer stx tx";
                                "txid" => %burn_tx.txid(),
                                "data" => %to_hex(&burn_tx.data()),
                                "error" => ?e,
                            );
                            None
                        }
                    }
```

**File:** stackslib/src/chainstate/burn/operations/transfer_stx.rs (L93-123)
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
```

**File:** stackslib/src/chainstate/burn/operations/transfer_stx.rs (L126-195)
```rust
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

**File:** stackslib/src/chainstate/burn/operations/transfer_stx.rs (L216-227)
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
```

**File:** stackslib/src/chainstate/burn/db/processing.rs (L75-81)
```rust
            BlockstackOperationType::TransferStx(ref op) => op.check().map_err(|e| {
                warn!(
                    "REJECTED({}) transfer stx op {} at {},{}: {:?}",
                    op.block_height, &op.txid, op.block_height, op.vtxindex, &e
                );
                BurnchainError::OpError(e)
            }),
```

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L4221-4249)
```rust
    /// Process any STX transfer bitcoin operations
    ///  that haven't been processed in this Stacks fork yet.
    pub fn process_transfer_ops(
        clarity_tx: &mut ClarityTx,
        mut operations: Vec<TransferStxOp>,
    ) -> Vec<StacksTransactionReceipt> {
        operations.sort_by_key(|op| op.vtxindex);
        let (all_receipts, _) =
            clarity_tx.with_temporary_cost_tracker(LimitedCostTracker::new_free(), |clarity_tx| {
                operations
                    .into_iter()
                    .filter_map(|transfer_stx_op| {
                        let TransferStxOp {
                            sender,
                            recipient,
                            transfered_ustx,
                            txid,
                            burn_header_hash,
                            memo,
                            ..
                        } = transfer_stx_op.clone();
                        let result = clarity_tx.connection().as_transaction(|tx| {
                            tx.run_stx_transfer(
                                &sender.clone().into(),
                                &recipient.clone().into(),
                                transfered_ustx,
                                &BuffData { data: memo },
                            )
                        });
```
