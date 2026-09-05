### Title
Unauthenticated `TransferStxOp.sender` forgery via attacker-controlled `PreStxOp.output` drains arbitrary victim STX balances - ([File: stackslib/src/chainstate/burn/operations/transfer_stx.rs])

### Summary
`TransferStxOp::parse_from_tx` accepts a `sender` argument that is derived entirely from `PreStxOp.output`, which itself is just the first Bitcoin output address of a `PreStxOp` transaction that the *attacker* creates. Since paying Bitcoin funds to an address requires no proof of ownership of that address's private key, an attacker can name any victim's Stacks-equivalent address as the `sender`, then follow up with a self-signed `TransferStxOp` moving the victim's entire STX balance to themselves.

### Finding Description
The broken equality is: **STX moved out of an account == STX that account's owner authorized to move**. For ordinary Stacks transactions this is enforced by signature/auth checks in `StacksTransactionAuth`. `TransferStxOp`, however, is a *burnchain* operation, and its `sender` is not proven by any Stacks-level signature at all.

Trace:
1. `PreStxOp` is any Bitcoin transaction; its `output` field is simply "the first output address of a bitcoin tx that a burnchain observer decodes into a `StacksAddress`" [1](#0-0) . Nothing checks that the creator of this Bitcoin tx controls the private key behind that output address — sending BTC to an address never requires owning it.
2. When a `TransferStxOp` is parsed, the burnchain scanner looks up the `PreStxOp` referenced by the spent UTXO and passes `&pre_stx.output` directly as the `sender` of the `TransferStxOp`, with zero additional validation: [2](#0-1) 
3. Inside `TransferStxOp::parse_from_tx`, `sender` is stored verbatim, and `transfered_ustx` is parsed straight from the tx payload with no upper bound, no relation to any burnt amount, and no signature check: [3](#0-2) 
4. `check()` only rejects a zero amount or self-send — it never validates `sender` authorization or bounds `transfered_ustx` against the sender's actual balance: [4](#0-3) 
5. `process_transfer_ops` then unconditionally calls `run_stx_transfer(sender, recipient, transfered_ustx, memo)` inside `clarity_tx.connection().as_transaction(...)`, which directly manipulates the Clarity STX ledger and bypasses normal Stacks transaction authorization entirely: [5](#0-4) 

Exploit flow: The attacker crafts a Bitcoin `PreStxOp` transaction with `output[0]` = the Bitcoin-address-equivalent of the victim's Stacks address (which requires only public knowledge of the victim's address hash160, not their private key) and `output[1]` = an address the attacker controls. The attacker then spends `output[1]` (which they own and can sign for) in a `TransferStxOp` transaction, setting `recipient` = themselves and `transfered_ustx` = the victim's full balance. The victim never signs or broadcasts anything. Existing guards (`check()`, `parse_from_tx` bounds, opcode/format checks) validate only the wire format and self-send condition — none of them verify that the party constructing the burnchain transaction pair actually controls the named `sender` Stacks/Bitcoin address.

### Impact Explanation
This allows any unprivileged attacker to steal the entire STX balance of any arbitrary victim address, with no interaction, signature, or consent from the victim required — this is a Critical, full theft-of-funds impact, matching "theft ... of locked STX" (here, unlocked/liquid STX, an even more direct case) and is fully repeatable against any victim account for any amount up to their balance, limited only by the attacker's cost of one Bitcoin transaction.

### Likelihood Explanation
Preconditions are minimal and attacker-controlled: the victim need only hold a nonzero STX balance and need never have transacted with the attacker. Any account with sufficient BTC to pay Bitcoin transaction fees for two chained Bitcoin transactions can execute the attack; no PoX cycle phase, membership state, pause/bond-admin role, or victim signature is required. This is a low-cost, highly feasible, and repeatable attack.

### Recommendation
`TransferStxOp` (and similarly `StackStxOp`/`DelegateStxOp`, which follow the identical `PreStxOp.output`-as-sender pattern) must not treat the `PreStxOp.output` field as an authenticated `sender`. Require cryptographic proof that the entity broadcasting the `PreStxOp`/`TransferStxOp` pair controls the private key corresponding to `sender` (e.g., require the `PreStxOp` itself be spent from a UTXO whose scriptPubKey hash matches the designated sender's key, or require an accompanying Stacks-signed authorization message binding sender to the specific transfer amount/recipient) before allowing `run_stx_transfer` to move funds out of that account.

### Proof of Concept
Rust integration test plan on a booted `TestPeer`/mock burnchain:
1. Seed a "victim" Stacks account with balance `X` via genesis/boot; assert `victim balance == X`.
2. As the attacker only (using attacker-owned BTC UTXOs and keys), construct a `BurnchainTransaction` for `PreStxOp` with `output[0]` = Bitcoin address equivalent to the victim's Stacks address hash160, `output[1]` = attacker-controlled address; submit and mine it.
3. As the attacker only, construct a `TransferStxOp` Bitcoin transaction spending `output[1]` (vout=1) from step 2, with recipient = attacker, `transfered_ustx = X`; submit and mine it.
4. Run the chainstate forward through `process_transfer_ops`.
5. Assert equality before: `victim_balance_before == X`, `attacker_balance_before == 0`.
6. Assert equality after: `victim_balance_after == 0`, `attacker_balance_after == X`, with no Stacks transaction signed by, or referencing a public key of, the victim appearing anywhere in the chainstate — proving the AUTHORITY equality (funds moved == funds the owner authorized) is broken.

### Citations

**File:** stackslib/src/burnchains/burnchain.rs (L881-899)
```rust
            x if x == Opcodes::PreStx as u8 => {
                match PreStxOp::from_tx(
                    block_header,
                    epoch_id,
                    burn_tx,
                    burnchain.pox_constants.sunset_end,
                ) {
                    Ok(op) => Some(BlockstackOperationType::PreStx(op)),
                    Err(e) => {
                        warn!(
                            "Failed to parse pre stack stx tx";
                            "txid" => %burn_tx.txid(),
                            "data" => %to_hex(&burn_tx.data()),
                            "error" => ?e,
                        );
                        None
                    }
                }
            }
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

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L4223-4249)
```rust
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
