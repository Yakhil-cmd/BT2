### Title
Unsigned STX locking via forged `PreStxOp.output` in `StackStxOp` — attacker can lock a victim's STX without any Stacks-side signature - (File: `stackslib/src/chainstate/burn/operations/stack_stx.rs`)

### Summary
`PreStxOp::parse_from_tx` accepts any Bitcoin output address as the future `sender` with no check that the transaction's own inputs (i.e., the party who actually signs and controls the PreStx tx) correspond to that address's key. `StackStxOp::get_sender_txid` only enforces that the follow-up tx spends vout=1 of that specific PreStx tx, which the attacker itself created and controls. The resulting `StackStxOp.sender` is fed directly as the Clarity `tx-sender` into `.pox-4`'s `stack-stx` via `run_contract_call`, with no Stacks-native signature check on `sender` at all.

### Finding Description
The broken equality: `StackStxOp.sender` (the principal whose STX actually gets locked in `.pox-4`) is claimed to equal "an address whose Bitcoin-input custody the transaction author has proven." In reality, `sender` only equals *whatever address the attacker wrote into `outputs[0]`* of a Bitcoin transaction the attacker fully authored — a value with zero cryptographic relationship to the attacker's actual signing key.

Code path:
1. `PreStxOp::parse_from_tx` (`stackslib/src/chainstate/burn/operations/stack_stx.rs:74-144`) takes `outputs.get(0)` and decodes it into a `StacksAddress` via `try_into_stacks_address()`, with no check that this output's pubkey hash matches any of the transaction's own inputs' signing keys. [1](#0-0) 
2. `StackStxOp::get_sender_txid` only verifies that the StackStx tx's first input spends `vout == 1` of the referenced PreStx txid — it does not verify who signed the PreStx tx's inputs relative to `output`. [2](#0-1) 
3. `burnchain.rs` wires `pre_stack_stx.output` directly in as `sender` for `StackStxOp::from_tx`. [3](#0-2) 
4. `process_stacking_ops` executes the Clarity `stack-stx` call using `sender.clone().into()` as the acting principal (`tx-sender` inside the contract), with no Stacks transaction signature ever verified for this `sender`. [4](#0-3) 
5. Inside `.pox-4`'s `stack-stx`, the only "authorization" performed is a balance check (`stx-get-balance tx-sender`) and a signer-key-ownership check for the *signer*, not the *stacker*. Nothing verifies that `tx-sender` (`sender`) consented. [5](#0-4) 

Attacker's exact call sequence: attacker builds a PreStx Bitcoin tx using only their own BTC input(s), sets `outputs[0].address` = the legacy Bitcoin address that hash160-maps to the victim's `StacksAddress` (public information, since Stacks addresses are `version + hash160(pubkey)`), and `outputs[1]` = attacker's own change. Since the attacker created and fully controls this tx (their own inputs), they alone hold the key that can later spend `outputs[1]`. They then build a StackStx tx spending `outputs[1]` (attacker's own key), naming an attacker-controlled `reward_addr`. `StackStxOp.sender` becomes the victim's address purely by the attacker's unilateral choice in step 1 — no proof of key ownership over the victim's hash160 is ever required, because sending Bitcoin *to* an address requires no private key for that address.

Existing guards do not prevent this: `check-caller-allowed`/direct-call checks are irrelevant to burn-op-originated calls (`TransactionOrigin::Burn`), `consume-signer-key-authorization` only validates the *signer key*'s ownership/consent for a given pox-addr/cycle, not the *stacker*'s consent, and no code path ties `PreStxOp.output` back to the PreStx tx's own input-signing key.

### Impact Explanation
If the named victim address holds unlocked STX ≥ the amount the attacker requests, that STX is locked into `.pox-4` for up to `POX_MAX_NUM_CYCLES` reward cycles under a `reward_addr` the attacker fully controls — meaning the attacker collects the PoX BTC rewards for stacking STX they never owned, while the victim's STX is frozen without consent for the lock period (STX auto-unlocks to the victim at `unlock-burn-height`, so this is a *temporary* freeze plus theft of the associated reward stream, not a permanent freeze or fund transfer of principal). This matches the "temporary freezing of staked funds" / "an unsigned stacking action" High-severity category. It is repeatable against any address whose balance and Bitcoin-mapped address the attacker can observe on-chain, and costs the attacker only Bitcoin transaction fees plus the dust amounts for the two chained outputs.

### Likelihood Explanation
No privileged role is required — the described attacker persona ("craft burnchain stacking ops from their own Bitcoin inputs, and order their own transactions") explicitly covers this. The only precondition is that the victim has unlocked STX at the target address and is not already stacking/delegating (checked by the contract, but this doesn't block the attacker — it only blocks stacking the same address twice). This is fully feasible with two ordinary Bitcoin transactions and standard node behavior; it requires no cooperation, signature, or private key from the victim.

### Recommendation
Bind `PreStxOp.output` cryptographically to the PreStx transaction's own input signer(s) — e.g., require `outputs[0]`'s pubkey hash to match the hash160 of the public key(s) used to sign the PreStx transaction's inputs (analogous to how the miner's own key is used in `build_pre_stacks_tx`), rejecting `PreStxOp`s whose declared `sender` is not provably the same key that funded/signed the transaction.

### Proof of Concept
Rust test in `stackslib/src/chainstate/burn/operations/stack_stx.rs` test module:
1. Construct `victim_addr = StacksAddress::new(...)` with a hash160 the test does NOT hold the private key for.
2. Construct a `BitcoinTransaction` for the PreStx op whose single input is signed/keyed by an unrelated `attacker_key`, and whose `outputs[0].address` decodes to `victim_addr`, `outputs[1]` is attacker's own change address.
3. Call `PreStxOp::parse_from_tx(...)` and assert `op.output == victim_addr` succeeds despite no relationship between `attacker_key` and `victim_addr`.
4. Construct the StackStx tx whose input's `tx_ref` is `(pre_stx_txid, 1)` (spending attacker's own change output), and call `StackStxOp::parse_from_tx(..., sender=&victim_addr, ...)`; assert `op.sender == victim_addr`.
5. Feed the resulting `StackStxOp` through `process_stacking_ops` (`stackslib/src/chainstate/stacks/db/blocks.rs`) against a chainstate where `victim_addr` holds a funded, unlocked STX balance that the test never signed a transaction from; assert the resulting `stx-account victim_addr` shows `locked > 0` and `stacking-state` entry keyed on `victim_addr`, despite no Stacks transaction ever being signed by the victim's key.

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

**File:** stackslib/src/burnchains/burnchain.rs (L929-954)
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

**File:** contrib/boot-contracts-unit-tests/boot_contracts/pox-4.clar (L591-604)
```text
      ;; tx-sender principal must not be stacking
      (asserts! (is-none (get-stacker-info tx-sender))
        (err ERR_STACKING_ALREADY_STACKED))

      ;; tx-sender must not be delegating
      (asserts! (is-none (get-check-delegation tx-sender))
        (err ERR_STACKING_ALREADY_DELEGATED))

      ;; the Stacker must have sufficient unlocked funds
      (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
        (err ERR_STACKING_INSUFFICIENT_FUNDS))

      ;; Validate ownership of the given signer key
      (try! (consume-signer-key-authorization pox-addr (- first-reward-cycle u1) "stack-stx" lock-period signer-sig signer-key amount-ustx max-amount auth-id))
```
