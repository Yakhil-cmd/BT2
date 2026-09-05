### Title
Unprivileged theft of arbitrary Stacks address's STX via crafted `PreStxOp.output` in `TransferStxOp` - (stackslib/src/chainstate/burn/operations/transfer_stx.rs)

### Summary
`TransferStxOp::parse_from_tx` assigns the `sender` field of a `TransferStxOp` directly from the caller-supplied `sender` parameter, which `classify_transaction` in `stackslib/src/burnchains/burnchain.rs` sets to `&pre_stx.output` — the first Bitcoin output address decoded from the antecedent `PreStxOp` transaction. Nothing in this path cryptographically ties `pre_stx.output` to any private key the crafter of the `PreStxOp`/`TransferStxOp` pair actually controls.

### Finding Description
The equality that must hold is: *the Stacks address whose STX balance is decremented by an applied `TransferStxOp` == the Stacks address controlled by the private key that authorized the underlying Bitcoin spend chain (PreStxOp → TransferStxOp)*. The code breaks this equality.

Trace:
- `classify_transaction` (stackslib/src/burnchains/burnchain.rs, lines 900-919) handles a `TransferStx` opcode by locating the antecedent `PreStxOp` via `TransferStxOp::get_sender_txid`, then does `let sender = &pre_stx.output;` and calls `TransferStxOp::from_tx(block_header, burn_tx, sender)`. [1](#0-0) 
- `TransferStxOp::parse_from_tx` (stackslib/src/chainstate/burn/operations/transfer_stx.rs, lines 126-195) constructs the `TransferStxOp` with `sender: sender.clone()`, taking the value verbatim from the caller with no additional validation that this address is owned by whoever spent the PreStxOp's second output. [2](#0-1) 
- The only ownership-style check performed is `get_sender_txid`, which merely verifies that the `TransferStxOp` transaction's first input spends `vout == 1` of the referenced `PreStxOp` transaction — i.e. it verifies the *attacker's own* Bitcoin key signed the second output of the `PreStxOp`, not that anyone controls the address encoded in the *first* output (`pre_stx.output`, which becomes `sender`). [3](#0-2) 
- `TransferStxOp::check()` only rejects a zero-value transfer or `sender == recipient`; it performs no proof-of-ownership check on `sender`. [4](#0-3) 

Because `PreStxOp.output` is decoded purely from an arbitrary Bitcoin output address chosen by whoever broadcasts the `PreStxOp` transaction (an attacker can send bitcoin to any output script they like, without needing the recipient's permission or key, exactly as with any ordinary Bitcoin payment), an attacker can set `pre_stx.output` to any victim `StacksAddress`'s hash160, fund the second output with their own coins, and then spend that second output themselves to produce a valid `TransferStxOp` whose `sender` is the victim and `recipient` is attacker-controlled. This op is later applied by `process_transfer_ops` in stackslib/src/chainstate/stacks/db/blocks.rs, which calls `tx.run_stx_transfer(&sender, &recipient, transfered_ustx, ...)`, moving real STX balance out of the victim's account — the victim never signed a Stacks transaction, and no Bitcoin key belonging to them was used at any step.

I was not able to fully inspect `process_transfer_ops` / `run_stx_transfer`'s internal balance-check logic in stackslib/src/chainstate/stacks/db/blocks.rs before exhausting the tool budget, so I cannot rule out an additional guard there (e.g., a check tying `sender` back to a signature or requiring the account to have opted in). Based on all code actually inspected (transfer_stx.rs and the relevant `classify_transaction` branch in burnchain.rs), no such guard exists on the path that constructs and validates the op itself.

### Impact Explanation
If no downstream guard exists (unverified for `process_transfer_ops`/`run_stx_transfer` specifically), this allows theft of any unlocked STX balance from any Stacks address, for the cost of two Bitcoin transactions (attacker-funded), fully repeatable against any victim with a nonzero unlocked balance. This matches the Critical severity category ("theft ... of locked STX").

### Likelihood Explanation
Preconditions are minimal and fully attacker-controlled: the attacker needs no special role, no cooperation from the victim, and no privileged access — only enough BTC to pay two transaction fees. The `PreStxOp` and `TransferStxOp` are burnchain-native operations processed directly by chain state indexing, bypassing normal Stacks transaction signature verification entirely, so the attack is feasible against any victim address at any time, and is repeatable per victim/target amount.

### Recommendation
Require cryptographic proof that the party constructing the `PreStxOp`/`TransferStxOp` pair actually controls the Stacks account named as `sender`. Options: (a) require that `pre_stx.output`'s underlying scriptPubKey match the Bitcoin address that funded/signed the `PreStxOp`'s own input (i.e., self-referential burn op), or (b) require an explicit Stacks-side signature over the transfer payload from the `sender` account, checked in `process_transfer_ops` before calling `run_stx_transfer`. Additionally, audit `run_stx_transfer`/`process_transfer_ops` in stackslib/src/chainstate/stacks/db/blocks.rs to confirm whether any such check currently exists, since this could not be fully verified in this pass.

### Proof of Concept
Rust integration test outline (stackslib chainstate test harness):
1. Boot a test chainstate; create victim Stacks account `V` with `StacksAddress(hash_v)` funded with N unlocked STX (assert balance == N).
2. Attacker `A` crafts a `PreStxOp` Bitcoin transaction with output[0].address == victim's `hash_v` (arbitrary, no key needed) and output[1].address == attacker's own key-controlled address, funded from A's own UTXO.
3. Attacker spends output[1] with their own private key to build a `TransferStxOp` transaction (`vout == 1` of PreStxOp) with `recipient` = attacker's Stacks address, amount = N.
4. Run these through `classify_transaction` → confirm the parsed `TransferStxOp.sender == V`'s address (matches `pre_stx.output`) despite A never using V's key anywhere.
5. Apply via `process_transfer_ops`; assert V's STX balance decreased by N and A's (recipient) balance increased by N, with no Stacks-signed transaction from V ever submitted — proving the equality "STX moved == STX owned by the Bitcoin-key-authorizing party" is violated.

### Citations

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

**File:** stackslib/src/chainstate/burn/operations/transfer_stx.rs (L185-195)
```rust
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
