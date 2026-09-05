This confirms the mechanism. `process_transfer_ops` calls `tx.run_stx_transfer(&sender.into(), &recipient.into(), transfered_ustx, ...)` unconditionally on success, with no signature or authorization check tied to `sender` beyond what `TransferStxOp::check()` validates (amount > 0, sender != recipient).### Title
Unauthenticated `sender` binding in `TransferStxOp` allows theft of any Stacks address's STX via a spoofed `PreStxOp` output - ([File: stackslib/src/chainstate/burn/operations/transfer_stx.rs], [File: stackslib/src/chainstate/burn/operations/stack_stx.rs], [File: stackslib/src/burnchains/burnchain.rs])

### Summary
`Burnchain::classify_transaction` derives the `sender` of a `TransferStxOp` purely from the attacker-controlled `PreStxOp.output` field, with no cryptographic proof that the entity naming that address as `output` actually controls it. An attacker can name any victim's Stacks address as the `PreStxOp` output, then spend the matching second output (vout=1) themselves to submit a `TransferStxOp` naming their own address as recipient, and `process_transfer_ops` unconditionally executes the STX transfer from the victim to the attacker.

### Finding Description
The broken equality: the STX debited from `sender` should equal STX actually owned/authorized by the entity signing the Bitcoin transactions, but `sender` is set to an arbitrary address chosen by whoever creates the `PreStxOp` output field, not the signer of any Bitcoin input.

Code path:
1. `PreStxOp::parse_from_tx` (stack_stx.rs:74-144) takes `output` directly from the transaction's first output address with **no check** that it corresponds to the party who signed the tx's inputs: [1](#0-0) 
2. `Burnchain::classify_transaction` for `Opcodes::TransferStx` looks up the referenced `PreStxOp` by the txid the `TransferStxOp`'s first input spends (must be vout=1), and sets `sender = &pre_stx.output` unconditionally: [2](#0-1) 
3. `TransferStxOp::parse_from_tx` sets `recipient` to the first output of the `TransferStxOp` Bitcoin transaction, entirely attacker-controlled: [3](#0-2) 
4. `TransferStxOp::check()` only validates `transfered_ustx > 0` and `sender != recipient` — no signature or ownership check: [4](#0-3) 
5. `process_transfer_ops` executes `tx.run_stx_transfer(&sender.into(), &recipient.into(), transfered_ustx, ...)` unconditionally on success: [5](#0-4) 

Exploit flow: the attacker crafts a `PreStxOp` Bitcoin transaction funded entirely with their own BTC, with output[0] = the victim's Stacks address (encoded as a Bitcoin address) and output[1] = change back to the attacker. The attacker then spends output[1] (vout=1) in a second Bitcoin transaction carrying the `TransferStx` opcode, whose OP_RETURN payload specifies `transfered_ustx`, and whose first output is the attacker's own address. Because `get_sender_txid` (transfer_stx.rs:93-110) only checks that the spent input is vout=1 of the referenced PreStx txid — a condition trivially satisfiable since the attacker controls that UTXO — the op is classified as a valid `TransferStxOp{sender: victim, recipient: attacker, transfered_ustx}`. No Stacks-layer signature, nonce, or post-condition from the victim is ever required, since this is a burnchain (Bitcoin) operation, not a signed `StacksTransaction`.

No existing guard prevents this: `PreStxOp` performs no address-ownership check; `TransferStxOp::check` performs no sender-authorization check; `process_transfer_ops` performs no additional authorization before calling `run_stx_transfer`.

### Impact Explanation
Critical theft of the victim's real, spendable STX balance. The attacker gains `transfered_ustx` STX per exploit transaction from any address they can name (subject to the victim's on-chain balance being ≥ the transferred amount) with zero victim-authorized transaction. This is fully repeatable against any address with a nonzero STX balance and is directly a case of "STX debited from `sender` != STX actually owned/authorized by the Bitcoin-signing attacker" — a clean theft of locked/liquid STX, matching the Critical severity bar (theft of STX).

### Likelihood Explanation
Preconditions are minimal and fully attacker-controlled: the attacker needs only enough BTC to fund two low-value Bitcoin transactions (a `PreStxOp` and a `TransferStxOp`), knowledge of the victim's Stacks address (public information), and the victim must simply hold ≥ `transfered_ustx` STX (no special cycle phase, membership, or contract state is required — this bypasses Clarity/pox contracts entirely, operating at the burnchain-classification layer). This requires no signer/miner/privileged role and is trivially repeatable against many victims and many times.

### Recommendation
Require that the Stacks `sender`/authorizing address for `TransferStxOp` (and `StackStxOp`/`DelegateStxOp`, which share the same pattern) be cryptographically derived from the actual signer(s) of the `PreStxOp`'s Bitcoin inputs (e.g., derive the Stacks address from the recovered public key(s) of the PreStx transaction's inputs, or otherwise require a signature proving control of the named `output` address) rather than trusting the arbitrary `output` field the transaction creator can set to any address.

### Proof of Concept
Rust integration test (extending `stackslib/src/burnchains/tests/db.rs::test_classify_stack_stx` pattern):
1. Construct a `PreStxOp` Bitcoin transaction funded solely by attacker-controlled UTXOs, with `outputs[0].address` = victim's Stacks address (converted to legacy Bitcoin address form), `outputs[1].address` = attacker's own change address.
2. Feed it through `BurnchainDB::store_new_burnchain_block` / `classify_transaction` and confirm it is parsed as `PreStxOp{ output: victim_address, .. }`.
3. Construct a second Bitcoin transaction with opcode `TransferStx`, `inputs[0] = (pre_stx_txid, 1)` (spending the attacker's change output), and `outputs[0].address` = attacker's own address, OP_RETURN payload encoding `transfered_ustx = N`.
4. Run `classify_transaction`/`get_blockstack_transactions` and assert the resulting op is `TransferStxOp{ sender: victim_address, recipient: attacker_address, transfered_ustx: N }`.
5. Seed chainstate so `victim_address` has an STX balance ≥ N (e.g., via genesis allocation), with no corresponding `StacksTransaction` ever signed by the victim.
6. Call `StacksChainState::process_transfer_ops` with this op and assert: before — `victim_balance == B`, `attacker_balance == A`; after — `victim_balance == B - N` and `attacker_balance == A + N`, proving STX moved without any victim-signed authorization.

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

**File:** stackslib/src/chainstate/burn/operations/transfer_stx.rs (L163-195)
```rust
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

**File:** stackslib/src/chainstate/burn/operations/transfer_stx.rs (L217-227)
```rust
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

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L4242-4249)
```rust
                        let result = clarity_tx.connection().as_transaction(|tx| {
                            tx.run_stx_transfer(
                                &sender.clone().into(),
                                &recipient.clone().into(),
                                transfered_ustx,
                                &BuffData { data: memo },
                            )
                        });
```
