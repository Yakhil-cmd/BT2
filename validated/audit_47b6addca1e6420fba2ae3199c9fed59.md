### Title
Any Bitcoin-transacting party can force-lock a victim Stacks address's STX into stacking via `PreStxOp`/`StackStxOp` with no Stacks-side signature - (File: `stackslib/src/chainstate/burn/operations/stack_stx.rs`)

### Summary
`StackStxOp::parse_from_tx` sets `sender` purely to the address recorded as the first output (`output`) of a previously-mined `PreStxOp`, and `StackStxOp::check` performs no signature verification tying that address to whoever crafted the burnchain transactions. Because a `PreStxOp`'s first output can pay to *any* address (paying someone BTC requires no cooperation from the recipient), and its second output (vout=1) is entirely controlled by whoever built the `PreStxOp` transaction, an attacker who never held address A's Stacks or Bitcoin private key can construct the `PreStxOp`→`StackStxOp` pair themselves and force `stack-stx` to be invoked with `tx-sender = A`.

### Finding Description
The broken equality: the identity that is locked via a burnchain `StackStxOp` (`sender`) must equal the identity that authorized the lock via a Stacks-side (or at minimum Bitcoin-side, cryptographically-bound) signature. In this codebase, `sender` is derived purely from Bitcoin UTXO topology with no signature check anywhere in the path:

- `PreStxOp::parse_from_tx` takes the transaction's first recipient output address verbatim as `output`, with no requirement that the output's owner authorized anything [1](#0-0) .
- `StackStxOp::get_sender_txid` only enforces that the spending input's `vout == 1` of the `PreStxOp` transaction, i.e. pure UTXO plumbing, not signer identity [2](#0-1) .
- In the burnchain op resolver, `sender` for the `StackStxOp` is taken directly from `pre_stack_stx.output` (i.e., the `PreStxOp`'s first-output address) and passed straight into `StackStxOp::from_tx` with no further validation [3](#0-2) .
- `StackStxOp::check()` validates positivity of `stacked_ustx`, `num_cycles` bounds, and (if present) that `signer_key` is a well-formed public key — it never checks any signature binding `sender` to the transaction's actual Bitcoin signers [4](#0-3) .
- `process_stacking_ops` then invokes `stack-stx` in the active PoX contract with `tx-sender = sender` (i.e., address A), using this Stacks address as the literal `tx-sender` principal for the Clarity call [5](#0-4) .
- The PoX contract's `stack-stx` (pox-4/pox-5 lineage) only requires that `tx-sender`'s balance covers `amount-ustx`; it has no notion of Bitcoin-side authorization at all — it simply trusts the `tx-sender` principal handed to it by the burnchain-op processor [6](#0-5) .

Exploit flow: attacker (controls Bitcoin key B, no Stacks/Bitcoin key for A) builds a Bitcoin transaction with opcode `PreStx`, output[0] = A's address (a plain payment, requiring no cooperation from A), output[1] = an address attacker controls. This is mined, producing a `PreStxOp` with `output = A`. Attacker then builds a second Bitcoin transaction with opcode `StackStx` whose input[0] spends `PreStxOp`'s vout=1 (which the attacker fully controls since they built output[1]); its other inputs can be signed by any of the attacker's other keys. The node resolves `sender = A` from the recorded `PreStxOp`, and `process_stacking_ops` runs `stack-stx` as `tx-sender = A`. If A holds enough spendable STX, A's STX becomes locked for `num_cycles`, with the PoX reward address set to whatever `reward_addr` the attacker specified in the `StackStxOp`'s first output — meaning any BTC stacking rewards attributable to A's locked STX accrue to an address the attacker controls, not to A.

No existing guard closes this gap: `check-caller-allowed`/`is-none (get-stacker-info tx-sender)`/balance sufficiency in the Clarity contract only constrain what `tx-sender` (already fixed to be A by the burnchain-op layer) can do — they presuppose that `tx-sender` was legitimately derived, which it is not.

### Impact Explanation
An attacker can force any sufficiently-funded Stacks address to have its STX locked for a stacking cycle without any consent, and can redirect the associated PoX BTC reward payout to an address the attacker controls (`reward_addr` is attacker-supplied). This matches the High-severity category: temporary freezing of staked funds (A's balance becomes locked against A's will for `num_cycles`), plus theft of reward/fee value (BTC rewards proportional to A's forced-locked STX accrue to the attacker's `reward_addr`) rather than to A. It is repeatable against any address with unlocked STX and is not gated by any privileged role — it only requires the attacker's own Bitcoin UTXOs.

### Likelihood Explanation
Preconditions are minimal: the victim A must simply hold spendable, unlocked STX (any typical account). No cycle-phase or membership state is required beyond what the PoX contract's own `stack-stx` guards check (not currently stacked/delegated). Attacker cost is one Bitcoin `PreStxOp` transaction (a normal payment to A, which costs the attacker only the value they choose to send A, none of which A needs to reciprocate) plus one `StackStxOp` transaction they fully control. This is fully feasible using only the tools already exercised in existing integration tests (`stacks-node/src/tests/neon_integrations.rs`, `stacks-node/src/tests/nakamoto_integrations.rs`) which construct `PreStxOp`/`StackStxOp` pairs directly, and is repeatable each cycle against any target address.

### Recommendation
Require that the `StackStxOp`/`PreStxOp` pair cryptographically prove that the party submitting the burnchain operation controls the Stacks-side identity being locked — e.g., require the `PreStxOp`'s first output to be spent (proving Bitcoin-key ownership of A) as part of establishing `sender`, or require an explicit Stacks-style signature over the `StackStxOp` payload from A's key (similar to the `signer_key`/`signer-sig` mechanism already used to authorize the *reward address*, extended to authorize the *stacker* identity itself) before locking any STX.

### Proof of Concept
Rust integration test (booted `neon`/`nakamoto` chainstate, modeled on existing `stx_transfer_btc_integration_test` in `stacks-node/src/tests/neon_integrations.rs`):
1. Fund victim Stacks address `A` (derived from a private key the "attacker" never generates/possesses in this test) with STX via `initial_balances`.
2. From an attacker-controlled Bitcoin signer (`miner_signer`/`btc_regtest_controller`), submit a `PreStxOp { output: A, .. }` — note the test harness only ever needs `A`'s `StacksAddress`, not its private key.
3. Submit a `StackStxOp` whose burnchain input spends vout=1 of the prior `PreStxOp` transaction, signed entirely with the attacker's own Bitcoin key(s), specifying `reward_addr` = attacker-controlled address and `stacked_ustx` ≤ A's balance.
4. Mine blocks until the ops are processed.
5. Assert: (a) `get_balance(A)` reflects a locked amount equal to `stacked_ustx` (i.e., A's unlocked balance decreased) even though no transaction was ever signed by A's Stacks or Bitcoin key; (b) query the PoX reward set / stacker-info to confirm the registered reward address is the attacker's `reward_addr`, not anything under A's control — confirming the equality "STX locked under A ⇔ A authorized the lock" does not hold.

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

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L398-420)
```rust
impl StackStxOp {
    pub fn check(&self) -> Result<(), op_error> {
        if self.stacked_ustx == 0 {
            warn!("Invalid StackStxOp, must have positive ustx");
            return Err(op_error::StackStxMustBePositive);
        }

        if self.num_cycles == 0 || self.num_cycles > POX_MAX_NUM_CYCLES {
            warn!(
                "Invalid StackStxOp, num_cycles = {}, but must be in (0, {}]",
                self.num_cycles, POX_MAX_NUM_CYCLES
            );
        }

        // Check to see if the signer key is valid if available
        if let Some(signer_key) = &self.signer_key {
            Secp256k1PublicKey::from_slice(signer_key.as_bytes())
                .map_err(|_| op_error::StackStxInvalidKey)?;
        }

        Ok(())
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

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L587-601)
```text
      ;; must be called directly by the tx-sender or by an allowed contract-caller
      (asserts! (check-caller-allowed)
                (err ERR_STACKING_PERMISSION_DENIED))

      ;; tx-sender principal must not be stacking
      (asserts! (is-none (get-stacker-info tx-sender))
        (err ERR_STACKING_ALREADY_STACKED))

      ;; tx-sender must not be delegating
      (asserts! (is-none (get-check-delegation tx-sender))
        (err ERR_STACKING_ALREADY_DELEGATED))

      ;; the Stacker must have sufficient unlocked funds
      (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
        (err ERR_STACKING_INSUFFICIENT_FUNDS))
```
