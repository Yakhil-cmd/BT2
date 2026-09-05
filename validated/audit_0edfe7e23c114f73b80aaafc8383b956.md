### Title
`TransferStxOp::check`'s `sender == recipient` guard is a no-op because both fields are independently spoofable, allowing STX to be moved from any victim address to any recipient address - ([File: stackslib/src/chainstate/burn/operations/transfer_stx.rs])

### Summary
`TransferStxOp::sender` is populated from the `output` field of a *separate*, attacker-crafted `PreStxOp` (vout0 of that earlier Bitcoin tx), while `TransferStxOp::recipient` is populated from vout0 of the `TransferStxOp`'s own Bitcoin tx. Neither field is checked against any Bitcoin key the transaction's signer actually controls, and neither is checked against any Stacks-level authorization (no signature from the Stacks private key of `sender`). The only real cryptographic proof supplied by the attacker is control of the UTXO at vout1 of the referenced `PreStxOp`, which is unrelated to the `sender`/`recipient` addresses. Because `check()` only verifies `transfered_ustx > 0` and `sender != recipient`, an attacker can trivially satisfy that inequality by using two distinct spoofed addresses (neither of which the attacker actually controls the Stacks key for) and still have the op processed, moving real STX between two unrelated victims/attacker-chosen accounts.

### Finding Description
Equality broken: `STX moved` (from the `sender` account, validated only by `run_stx_transfer`'s balance check) == `STX owned by an address that cryptographically authorized the move` (AUTHORITY). No such authorization exists in this path.

Code path:
1. `PreStxOp::parse_from_tx` sets `output` to vout0 of an arbitrary Bitcoin transaction, decoded via `try_into_stacks_address()` — this can be set to *any* Stacks address, not necessarily one the tx creator controls a key for: [1](#0-0) .
2. `TransferStxOp::get_sender_txid` requires the `TransferStxOp` Bitcoin tx to spend vout1 of that `PreStxOp` tx (proving control of the vout1 Bitcoin UTXO only) [2](#0-1) .
3. `burnchain.rs` looks up the referenced `PreStxOp` and passes its `output` field in as `sender` to `TransferStxOp::from_tx` [3](#0-2) .
4. `TransferStxOp::parse_from_tx` sets `recipient` from vout0 of the `TransferStxOp`'s own tx — again fully attacker-chosen, no key proof required [4](#0-3) .
5. `TransferStxOp::check` only rejects zero-amount transfers and `sender == recipient` self-sends; it performs no check binding `sender`/`recipient` to any Bitcoin or Stacks key the submitter controls: [5](#0-4) .
6. `process_transfer_ops` then executes `run_stx_transfer(&sender, &recipient, transfered_ustx, ...)` directly against the Clarity token ledger with no Stacks-transaction-style sender authentication (no signature check against `sender`'s Stacks key) — the STX moves as long as `sender`'s balance allows it: [6](#0-5) .

The attacker's exact call: craft `PreStxOp` #1 with vout0 = victim A's address (arbitrary, no key needed) and a spendable vout1 UTXO the attacker controls; craft `TransferStxOp` spending that vout1, with the `TransferStxOp`'s own vout0 = victim B's (or attacker's) address, and payload amount = victim A's balance. Since `sender` (victim A) != `recipient` (victim B), the `check()` self-send guard passes trivially, and the STX moves from A to B with no participation, signature, or consent from either A or B.

### Impact Explanation
This allows theft of STX from any account (`sender`), moved to any account (`recipient`) chosen by the attacker, entirely unauthenticated by any key belonging to `sender` or `recipient`. This matches "Critical: theft ... of locked STX" — although here it applies to any (locked or unlocked) STX balance associated with a Stacks address, since the transfer bypasses Stacks-transaction-level signature authorization entirely. It is repeatable per distinct `PreStxOp`/`TransferStxOp` Bitcoin transaction pair, limited only by Bitcoin transaction fees, and does not require compromising any private key of the victim.

### Likelihood Explanation
Preconditions: attacker only needs to broadcast two Bitcoin transactions (a `PreStxOp` and a `TransferStxOp` spending its vout1) using their own BTC UTXOs — well within the defined "unprivileged attacker" capabilities ("craft burnchain stacking ops from their own Bitcoin inputs"). No pox-5 contract interaction, no signer role, no miner role is required. Cost is limited to Bitcoin transaction fees. This is fully repeatable against any target address with a nonzero STX balance.

### Recommendation
`TransferStxOp` (and the analogous `StackStxOp`/`DelegateStxOp` sender derivation) must not treat an arbitrary, self-declared Bitcoin output address as an authenticated Stacks "sender." Either require that the `PreStxOp`'s vout0 address be cryptographically derivable from the Bitcoin key that signs the `PreStxOp`'s own inputs (proving the submitter owns that identity), and reject transfers where the submitter cannot prove control over `sender`, or deprecate/restrict `TransferStxOp` to only apply to accounts explicitly designated at genesis (its original intended purpose) rather than allowing free-form third-party sender/recipient addresses.

### Proof of Concept
Rust integration test (based on existing harness in `stacks-node/src/tests/epoch_21.rs`):
1. Fund an unrelated account "Victim A" with STX via genesis/faucet; do not give the test attacker Victim A's private key.
2. Submit `PreStxOp { output: victim_a_addr, ... }` from an attacker-controlled BTC UTXO.
3. Submit `TransferStxOp` spending vout1 of that `PreStxOp`, with `transfered_ustx: <Victim A's balance>`, whose own vout0 encodes `recipient = victim_b_addr` (also not attacker-owned).
4. Mine the block; assert `sender == victim_a_addr`, `recipient == victim_b_addr` in the confirmed burn op (as in existing test assertions at `stacks-node/src/tests/nakamoto_integrations.rs:5405-5406`).
5. Query Victim A's and Victim B's STX balances before/after: assert Victim A's balance decreased by `transfered_ustx` and Victim B's increased by the same, despite neither Victim A nor Victim B signing or consenting to any transaction — demonstrating `STX moved != STX owned by an address that authorized the move`.

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

**File:** stackslib/src/burnchains/burnchain.rs (L900-920)
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
```

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L4242-4252)
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
```
