### Title
Arbitrary STX theft via spoofed `sender` in `TransferStxOp` derived from unverified `PreStxOp` output[0] address - ([File: stackslib/src/chainstate/burn/operations/transfer_stx.rs])

### Summary
`TransferStxOp::parse_from_tx` accepts a `sender: &StacksAddress` argument that the caller (`Burnchain::classify_transaction`) sets to the address decoded from `PreStxOp` output[0], and `TransferStxOp::check` never validates that whoever spends `PreStxOp` output[1] to submit the `TransferStxOp` actually controls the private key behind that `sender` address. Since Bitcoin addresses/output scripts are public data, an attacker can construct their own `PreStxOp` with output[0] set to a victim's Stacks address and output[1] under attacker control, then spend output[1] to submit a `TransferStxOp` that drains the victim's account to an attacker-controlled recipient.

### Finding Description
The claimed broken equality is: **the Stacks account whose STX is debited by the applied `TransferStxOp` (`op.sender`) must equal the account actually authorized by the private key that signed the Bitcoin transaction chain producing the op**. In the code, `sender` is never derived from any signature or key check — it is decoded purely from the address bytes of `PreStxOp` output[0]: [1](#0-0) 

`get_sender_txid` only verifies that the *current* transaction's input references vout `1` of the referenced prior transaction — it never checks that the key used to spend that output matches the key that produced output[0] of the same prior transaction: [2](#0-1) 

`TransferStxOp::check` only rejects a zero transfer amount or `sender == recipient`; it performs no ownership/authority validation of `sender` at all: [3](#0-2) 

**Exploit flow:** the attacker crafts a `PreStxOp` Bitcoin transaction with output[0] = the victim's Stacks address (public, hash160-derived — no private key needed to reference it) and output[1] = an address the attacker controls. `Burnchain::classify_transaction` records this `PreStxOp` and its `output` field (= victim address) in its lookup map. The attacker then spends output[1] with their own key in a second transaction carrying `Opcodes::TransferStx`, setting the recipient output to an attacker-controlled address and `transfered_ustx` to the victim's full balance. `get_sender_txid` confirms the input spends vout 1 of the `PreStxOp` txid, `classify_transaction` looks up `sender = pre_stx_op.output` (the victim's address) and calls `TransferStxOp::from_tx(..., &sender)`, producing an op where `op.sender = victim`, `op.recipient = attacker`. `check()` passes because `transfered_ustx > 0` and `sender != recipient`. The chainstate then applies a real balance transfer debiting the victim and crediting the attacker.

No existing guard closes this gap: there is no requirement in `parse_from_tx`, `get_sender_txid`, or `check` that the signer of the spending transaction correspond to the `sender` address; the entire "authorization" for who the `sender` is rests on an unenforced convention that the same wallet controls both `PreStxOp` outputs.

### Impact Explanation
Critical — direct, unauthorized theft of a victim's unlocked STX. Any account balance can be targeted since only the victim's public Stacks address (not their private key) is required to name them as `sender`. This is fully repeatable against any address with a positive STX balance, and each successful `PreStxOp` + `TransferStxOp` pair drains the named victim's account in a single confirmed operation.

### Likelihood Explanation
Preconditions are minimal: the attacker needs their own Bitcoin UTXOs to fund the two-transaction `PreStxOp`/`TransferStxOp` sequence and only needs to know the victim's public Stacks address (trivially obtainable from any prior chain activity). No privileged role, signer key, or victim cooperation is required — this fits squarely within the allowed "attacker crafts burnchain stacking ops from their own Bitcoin inputs" capability. The attack is deterministic and repeatable against any funded address.

### Recommendation
Require verifiable cryptographic linkage between the `sender` Stacks address and the key that authorizes the follow-up op — e.g., derive `sender` from the actual input-spending key/script of the transaction that spends `PreStxOp` output[1] (or require output[0] and output[1] to resolve to the same address/key), rather than trusting the unauthenticated address bytes recorded in `PreStxOp` output[0].

### Proof of Concept
Rust test in `stackslib/src/chainstate/burn/operations/transfer_stx.rs` (or an integration test in `burnchain.rs`):
1. Construct `victim_addr` (arbitrary `StacksAddress`, no associated key needed) and `attacker_addr`/`attacker_key` (a real keypair controlled by the test).
2. Build a `PreStxOp`-shaped `BitcoinTransaction` with `outputs[0].address = victim_addr`-equivalent Bitcoin address and `outputs[1].address` spendable by `attacker_key`; feed through `Burnchain::classify_transaction` to register it.
3. Build a second `BitcoinTransaction` with `opcode = Opcodes::TransferStx`, input `tx_ref = (pre_stx_txid, 1)` (signed with `attacker_key`), and an output decoding to `attacker_addr` as recipient, with `transfered_ustx` set to the victim's simulated balance.
4. Call `Burnchain::classify_transaction` / `TransferStxOp::parse_from_tx` and assert `op.sender == victim_addr` and `op.recipient == attacker_addr` even though `attacker_key != victim's (nonexistent) key`.
5. Apply the op against a chainstate where `victim_addr` holds STX; assert `TransferStxOp::check(&op).is_ok()` and that post-application `victim`'s STX balance decreases by `transfered_ustx` while `attacker`'s balance increases by the same amount — demonstrating the sender-authority equality is violated.

### Citations

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
