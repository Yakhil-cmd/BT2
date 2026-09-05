### Title
Attacker-declared `PreStxOp.output` becomes an unauthenticated `sender` for `TransferStxOp`/`StackStxOp`, allowing STX theft/forced-locking of any address without its private key - (File: stackslib/src/chainstate/burn/operations/stack_stx.rs, transfer_stx.rs, stackslib/src/burnchains/burnchain.rs)

### Summary
`PreStxOp::parse_from_tx` accepts `output` (the future "sender") as the raw first Bitcoin output address of the PreStx transaction, which anyone can set to any Hash160 without owning its key. `classify_transaction` then propagates this `pre_stx.output` verbatim as `sender` into `StackStxOp`/`TransferStxOp`/`DelegateStxOp`, and `StacksChainState::process_transfer_ops`/`process_stacking_ops` use it directly as the Clarity STX-transfer/stack-stx origin with no signature check at all.

### Finding Description
The broken equality: the code implicitly assumes `sender (pre_stx.output, vout=0 of PreStxOp)` == `the party who can spend vout=1 of the same PreStxOp tx`. Nothing enforces this.

- `PreStxOp::parse_from_tx` takes outputs[0] of the PreStx Bitcoin transaction as `output`, with zero ownership verification [1](#0-0) . `SortitionHandleTx::check_transaction` explicitly performs `Ok(())` with no `check()` for PreStx [2](#0-1) .
- `Burnchain::classify_transaction` resolves the follow-up op's `sender` purely by looking up the referenced PreStxOp and taking `&pre_stx.output` — it never checks that the party signing the follow-up transaction's input (which must spend vout=1 of the PreStxOp, enforced only by `get_sender_txid`'s `vout != 1` check) is related to vout=0's address at all [3](#0-2) [4](#0-3) .
- `TransferStxOp::get_sender_txid`/`StackStxOp::get_sender_txid` only validate that the current tx's first input references `(pre_stx_txid, vout=1)` — proving the signer controls vout=1's key, not vout=0's identity [5](#0-4) [6](#0-5) .
- Downstream, `sender` is fed directly into `run_stx_transfer` (moves real STX) and `run_contract_call(...,"stack-stx",...)` with no signature validation against `sender` [7](#0-6) [8](#0-7) .

Attacker's exact call sequence:
1. Attacker builds a normal Bitcoin transaction (funded by their own UTXOs) with `PreStx` opcode, output[0] = victim's Hash160/StacksAddress (public knowledge, no key required to "pay" an address), output[1] = an address the attacker controls.
2. Attacker (or anyone) submits this PreStxOp; per `check_transaction`, PreStx has no validation and is unconditionally accepted.
3. Attacker crafts a second Bitcoin tx whose input[0] spends `(pre_stx_txid, vout=1)` — trivially valid since the attacker owns that key — carrying `TransferStx` (or `StackStx`) opcode data.
4. `classify_transaction` resolves `sender = pre_stx.output = victim address`, and the resulting `TransferStxOp{sender: victim, recipient: attacker, ...}` is applied via `run_stx_transfer`, moving the victim's real STX to the attacker with no victim signature ever checked. For `StackStxOp`, the victim's balance gets locked into PoX with a `reward_addr` chosen by the attacker, redirecting rewards.

Existing guards (`op.check()` for StackStx/TransferStx/DelegateStx) only validate amount ranges, cycle counts, and key format — never that `sender` corresponds to the entity that authorized the burnchain transaction. Nothing checks that `pre_stx.output` (vout=0) and the key spending vout=1 belong to the same wallet.

### Impact Explanation
An unprivileged attacker can direct a `TransferStxOp` moving any address's liquid STX to themselves (direct theft), or a `StackStxOp` that locks any address's STX into PoX under an attacker-chosen `reward_addr` (theft of PoX rewards plus involuntary/forced locking of the victim's funds — "permanent freezing of staked STX" and reward misdirection). This matches the Critical category: theft of STX and/or forced/unauthorized locking of funds never authorized by their owner. This is repeatable against any address whose Hash160 is publicly known (i.e., essentially any Stacks/Bitcoin address), at the cost of only a small Bitcoin transaction fee per attempt.

### Likelihood Explanation
Preconditions are trivial and fully within the described unprivileged attacker capability set ("craft burnchain stacking ops from their own Bitcoin inputs, order their own transactions"): the attacker needs no special role, no victim cooperation, and no compromise of Bitcoin/secp256k1. The only "cost" is broadcasting two ordinary Bitcoin transactions funded with the attacker's own UTXOs. This is feasible in any epoch supporting PreStx/StackStx/TransferStx (2.05+) and is repeatable against every address with a nonzero STX balance.

### Recommendation
Require that the address used as `sender` for `StackStxOp`/`TransferStxOp`/`DelegateStxOp` be cryptographically tied to whoever authorizes the follow-up spend — e.g., derive `sender` from the public key/script actually used to sign the input spending vout=1 of the PreStxOp (rather than trusting the attacker-supplied vout=0 address), or require vout=0 and vout=1 of the PreStxOp to use the identical script/pubkey hash and enforce that equality in `PreStxOp::parse_from_tx`/`check_transaction`.

### Proof of Concept
Rust test plan (extending existing burnchain op tests, e.g. `stackslib/src/burnchains/tests/db.rs`):
1. Construct a `BitcoinTransaction` for a PreStxOp with `outputs[0].bytes = Hash160([9;20])` (the "victim", attacker never generates this key) and `outputs[1].bytes = Hash160([7;20])` (attacker's own key, attacker holds the corresponding private key in the test).
2. Feed it through `Burnchain::classify_transaction` to get `BlockstackOperationType::PreStx(op)`; assert `op.output == StacksAddress::from_legacy_bitcoin_address(Hash160([9;20]))`.
3. Construct a follow-up `TransferStxOp` Bitcoin tx whose `inputs[0].tx_ref = (pre_stx_txid, 1)` (spending the attacker-controlled vout=1) and recipient = attacker's address.
4. Run it through `classify_transaction` and assert the resulting `TransferStxOp.sender == victim_address` (Hash160([9;20])) even though no input of this transaction, nor the PreStxOp, was ever signed by a key corresponding to Hash160([9;20]).
5. Feed the op through `StacksChainState::process_transfer_ops` against a chainstate where the victim address holds a nonzero STX balance, and assert the victim's balance decreases and attacker's balance increases — the equality to check is `victim_bitcoin_key_used_to_authorize == None` while `stx_debited_from == victim_address`, proving the mismatch.

Note: I was unable to locate/confirm the exact definition of `TransferStxOp::check()` (grep in `transfer_stx.rs` for `fn check` returned no match, so it may be implemented elsewhere or inherited); this does not change the conclusion since `check_transaction` in `processing.rs` shows `check()` only validates op-internal fields (amount/cycles/key format), not sender authenticity, for the sibling `StackStxOp`.

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

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L232-247)
```rust
    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!("Invalid tx: StackStxOp must spend the second output of the PreStxOp");
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: StackStxOp must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }
```

**File:** stackslib/src/chainstate/burn/db/processing.rs (L82-85)
```rust
            BlockstackOperationType::PreStx(_) => {
                // no check() required for PreStx
                Ok(())
            }
```

**File:** stackslib/src/burnchains/burnchain.rs (L900-928)
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
                } else {
                    warn!(
                        "Failed to find corresponding input to TransferStxOp";
                        "txid" => %burn_tx.txid(),
                        "pre_stx_txid" => %pre_stx_txid
                    );
                    None
                }
            }
```

**File:** stackslib/src/burnchains/burnchain.rs (L929-962)
```rust
            x if x == Opcodes::StackStx as u8 => {
                let pre_stx_txid = StackStxOp::get_sender_txid(burn_tx).ok()?;
                let pre_stx_tx = match pre_stx_op_map.get(pre_stx_txid) {
                    Some(tx_ref) => Some(BlockstackOperationType::PreStx(tx_ref.clone())),
                    None => burnchain_db.find_burnchain_op(indexer, pre_stx_txid),
                };
                if let Some(BlockstackOperationType::PreStx(pre_stack_stx)) = pre_stx_tx {
                    let sender = &pre_stack_stx.output;
                    match StackStxOp::from_tx(
                        block_header,
                        epoch_id,
                        burn_tx,
                        sender,
                        burnchain.pox_constants.sunset_end,
                    ) {
                        Ok(op) => Some(BlockstackOperationType::StackStx(op)),
                        Err(e) => {
                            warn!(
                                "Failed to parse stack stx tx";
                                "txid" => %burn_tx.txid(),
                                "data" => %to_hex(&burn_tx.data()),
                                "error" => ?e,
                            );
                            None
                        }
                    }
                } else {
                    warn!(
                        "Failed to find corresponding input to StackStxOp";
                        "txid" => %burn_tx.txid().to_string(),
                        "pre_stx_txid" => %pre_stx_txid.to_string()
                    );
                    None
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

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L4120-4130)
```rust
            let result = clarity_tx.connection().as_transaction(|tx| {
                tx.run_contract_call(
                    &sender.clone().into(),
                    None,
                    &boot_code_id(active_pox_contract, mainnet),
                    "stack-stx",
                    &args,
                    |_, _| None,
                    &ResourceBudget::unlimited(),
                )
            });
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
