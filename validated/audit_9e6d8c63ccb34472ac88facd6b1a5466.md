### Title
Unauthenticated `sender` binding in `TransferStxOp::parse_from_tx` allows theft of any victim's STX via forged `PreStxOp.output` - (File: stackslib/src/chainstate/burn/operations/transfer_stx.rs)

### Summary
`TransferStxOp::parse_from_tx` accepts `sender` as a parameter supplied by the caller (`burnchain.rs`), which sets it to `pre_stx.output` — a field on the linked `PreStxOp` that is pure attacker-controlled OP_RETURN data with no cryptographic tie to any Stacks private key. `TransferStxOp::check()` only validates `transfered_ustx != 0` and `sender != recipient`, never that the party spending the Bitcoin UTXO actually controls `sender`'s Stacks account, so an attacker can name any victim address as `sender` and have `process_transfer_ops` genuinely debit that victim's real STX balance.

### Finding Description
The claimed equality: total STX debited from any Stacks account via `TransferStxOp` == STX that account's actual owner authorized to move. This is broken because nothing in the parse/check/apply path verifies that the entity who creates the `PreStxOp`/`TransferStxOp` pair controls the Stacks private key for the address written into `PreStxOp.output`.

Trace:
1. `PreStxOp.output` is set from the Bitcoin tx's first output address, with no signature over a Stacks key — it is arbitrary data chosen by whoever crafts the PreStx Bitcoin transaction [1](#0-0) .
2. When a follow-up transaction spends vout=1 of that same PreStx tx, `burnchain.rs` looks up the corresponding `PreStxOp` and passes its `output` field directly as the `sender` for the new op, with zero ownership check: `let sender = &pre_stx.output; TransferStxOp::from_tx(block_header, burn_tx, sender)` [2](#0-1) .
3. `TransferStxOp::get_sender_txid` only checks that the spending tx's first input references vout=1 of *some* prior PreStx tx — a purely Bitcoin-UTXO-spending requirement that the attacker trivially satisfies because they created that PreStx tx themselves with their own BTC funds [3](#0-2) .
4. `TransferStxOp::parse_from_tx` builds the final op with `sender: sender.clone()` (the forged victim address) and `recipient: output` (attacker's chosen recipient, taken from the transfer tx's first output) [4](#0-3) .
5. `TransferStxOp::check()` performs no authorization check whatsoever beyond amount positivity and sender != recipient [5](#0-4) .
6. `process_transfer_ops` then unconditionally executes `tx.run_stx_transfer(&sender.into(), &recipient.into(), transfered_ustx, ...)` against the real Stacks account named `sender`, debiting its actual unlocked balance and crediting the attacker-controlled `recipient` [6](#0-5) .

Because the attacker fully controls the Bitcoin UTXO chain used for both the `PreStxOp` and the follow-up `TransferStxOp` spend, they can name any victim's Stacks address as `sender` and any address they own as `recipient`. No guard in the reachable path (`get_sender_txid`, `parse_from_tx`, `check`) validates that the Bitcoin signer has any relationship to the named `sender` Stacks account.

### Impact Explanation
Any account with a non-zero unlocked STX balance can have its funds moved to an attacker-chosen address with zero involvement from the account owner — a direct fund theft matching the "Critical - theft ... of ... locked STX" category (here, unlocked account balance, but the mechanism generalizes to any STX credited to the named address). The attack is repeatable per victim and can be fanned out across arbitrarily many victims using the same attacker-owned Bitcoin UTXO chain (one `PreStxOp` + `TransferStxOp` pair per victim), each new pair only costing Bitcoin transaction fees.

### Likelihood Explanation
Preconditions: the attacker needs only their own Bitcoin funds to create a PreStx tx and its follow-up spend transaction; no Stacks-side privilege, signer role, or victim cooperation is required. This works in any epoch where PreStx/TransferStx op processing is active (tests show it exercised across Epoch 2.05, 2.1, 2.5, and Nakamoto/Epoch 3.0). The cost per victim is minimal (two low-value Bitcoin transactions), and the attack is fully repeatable/automatable against any address with a real balance.

### Recommendation
Bind `TransferStxOp.sender` cryptographically to whoever actually authorizes the transfer, e.g., require that `PreStxOp.output`/the resulting `sender` match a Stacks address that is provably derived from the Bitcoin key that funds/spends the PreStx UTXO (or otherwise require an explicit Stacks-side signature/authorization from the named sender), rather than trusting attacker-supplied OP_RETURN data as the account to debit.

### Proof of Concept
Rust integration test plan (using existing test scaffolding, e.g. `stacks-node/src/tests/neon_integrations.rs` patterns):
1. Fund a victim's Stacks account with a known balance (e.g., via genesis allocation or a legitimate transfer) and record `victim_balance_before`.
2. As the attacker (using only attacker-owned BTC UTXOs), submit a `PreStxOp` with `output = victim_addr`.
3. Mine it; take the resulting tx's vout=1 UTXO.
4. As the attacker, spend that UTXO to submit a `TransferStxOp { sender: victim_addr, recipient: attacker_addr, transfered_ustx: victim_balance_before, ... }`, signed only with the attacker's own Bitcoin key.
5. Mine to process the op.
6. Assert `get_balance(victim_addr) == 0` (or `victim_balance_before - transferred`) and `get_balance(attacker_addr) == victim_balance_before` — proving the equality "STX moved out of victim == STX victim authorized (0)" is violated, with zero signatures or nonce from the victim.
7. Repeat steps 2-6 for 2 more distinct victim addresses using a single attacker UTXO chain to demonstrate fan-out drain of multiple accounts.

### Citations

**File:** stackslib/src/burnchains/tests/db.rs (L511-515)
```rust
    if let BlockstackOperationType::PreStx(op) = &processed_ops_0[0] {
        assert_eq!(&op.output, &expected_pre_stack_addr);
    } else {
        panic!("EXPECTED to parse a pre stack stx op");
    }
```

**File:** stackslib/src/burnchains/burnchain.rs (L906-909)
```rust
                if let Some(BlockstackOperationType::PreStx(pre_stx)) = pre_stx_tx {
                    let sender = &pre_stx.output;
                    match TransferStxOp::from_tx(block_header, burn_tx, sender) {
                        Ok(op) => Some(BlockstackOperationType::TransferStx(op)),
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

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L4242-4256)
```rust
                        let result = clarity_tx.connection().as_transaction(|tx| {
                            tx.run_stx_transfer(
                                &sender.clone().into(),
                                &recipient.clone().into(),
                                transfered_ustx,
                                &BuffData { data: memo },
                            )
                        });
                        match result {
                            Ok((value, _, events)) => {
                                debug!("Processed TransferStx burnchain op"; "transfered_ustx" => transfered_ustx, "sender" => %sender, "recipient" => %recipient, "txid" => %txid);
                                Some(StacksTransactionReceipt {
                                    transaction: TransactionOrigin::Burn(BlockstackOperationType::TransferStx(transfer_stx_op)),
                                    events,
                                    result: value,
```
