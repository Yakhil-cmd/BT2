### Title
Unauthenticated `StackStxOp.sender` binding allows an attacker to freeze a victim's STX and steal PoX rewards via forged `PreStxOp`/`StackStxOp` - (File: stackslib/src/chainstate/burn/operations/stack_stx.rs)

### Summary
`PreStxOp::parse_from_tx` derives the future stacking "sender" address purely from `tx.get_recipients()[0]` with no cryptographic tie to the key that signs the Bitcoin transaction's inputs. `StackStxOp::parse_from_tx`/`get_sender_txid` only verify that the `StackStxOp` transaction spends the PreStxOp's second output (vout=1); they never verify that the address encoded in the PreStxOp's first output belongs to whoever is spending that second output. Consequently an attacker can name any victim's `StacksAddress` as the `sender` and have `stack-stx` executed with `tx-sender = victim` while only the attacker signs the Bitcoin transactions.

### Finding Description
The broken equality: **"STX owner authorising the lock" == "STX owner whose Bitcoin key signed the operation"** is violated. `sender` should equal the Stacks account that cryptographically authorized the funds to be locked; instead it equals whatever `StacksAddress` an attacker writes into the PreStxOp's output[0].

Code path:
- `PreStxOp::parse_from_tx` (stack_stx.rs:74-144) takes `outputs.get(0)....address...try_into_stacks_address()` and stores it verbatim as `PreStxOp.output` [1](#0-0) . There is no check that this address's hash160 matches the public key that signed any of `tx`'s inputs.
- `StackStxOp::get_sender_txid` (stack_stx.rs:232-247) only checks that the spending input's `vout == 1`, i.e., that the StackStxOp transaction spends the PreStxOp's second output — it establishes which PreStxOp record to use, not who is authorized [2](#0-1) .
- `StackStxOp::parse_from_tx` then accepts `sender: &StacksAddress` as an external parameter and stores it directly as `StackStxOp.sender` with no further validation [3](#0-2) . `StackStxOp::check()` validates only `stacked_ustx`, `num_cycles`, and `signer_key` format — nothing about `sender`'s authorization [4](#0-3) .
- Downstream, `StacksChainState::process_stacking_ops` executes the pox contract's `stack-stx` with `tx.run_contract_call(&sender.clone().into(), ...)`, i.e., Clarity's `tx-sender` is set to the attacker-chosen victim address [5](#0-4) .
- In `pox-4.clar`'s `stack-stx`, the only checks are that `tx-sender` (=victim) is not already stacking/delegating, has sufficient balance, and that the `signer-key`/`signer-sig` pair is authorized for the chosen reward `pox-addr` — this authenticates the *signer*, not the *stacker* [6](#0-5) . Nothing requires the victim's own signature or key.

Exploit flow: attacker crafts a Bitcoin `PreStxOp` tx whose output[0] address hash equals the victim's `StacksAddress` bytes and whose output[1] is an attacker-controlled UTXO; once mined, the attacker spends output[1] in a `StackStxOp` tx (signed only by the attacker), setting `reward_addr` (from the StackStxOp tx's own output[0]) to an address the attacker controls, and `stacked_ustx` up to the victim's real unlocked balance. `Burnchain::classify_transaction` resolves `sender = pre_stx.output` = victim, and `process_stacking_ops` locks the victim's STX under `pox-4`, sending future BTC rewards to the attacker's `reward_addr`.

### Impact Explanation
The victim's STX get locked (frozen) for `num_cycles` reward cycles without any signature or consent from the victim — matching "permanent/temporary freezing of staked STX." Simultaneously, the attacker names themselves as the `reward_addr`, redirecting BTC PoX rewards that should correspond to no legitimate committed capital of their own to themselves — an unsigned/unauthorized stacking action and reward theft. This is repeatable against any victim account with sufficient unlocked STX balance and costs the attacker only Bitcoin transaction fees for two on-chain transactions.

### Likelihood Explanation
Preconditions are minimal: the victim only needs a known `StacksAddress` (public information) with unlocked STX and no pre-existing stacking/delegation state; the attacker needs any Bitcoin UTXO to fund the two-transaction sequence and control over a signer key/authorization for their own chosen `pox-addr`. No privileged role, node compromise, or miner collusion is required — purely a burnchain-op construction using the attacker's own keys. This makes the attack cheap, fully attacker-controlled, and repeatable for any number of victims per reward cycle (subject to the victim's balance not already being locked).

### Recommendation
Cryptographically bind the `sender` of a stacking burnchain operation to the actual signer of the Bitcoin transaction rather than trusting an arbitrary output address: e.g., require that `PreStxOp.output`'s hash160 match the hash160 derived from the public key(s) that sign input 0 of the *same* PreStxOp transaction (or equivalently of the `StackStxOp` transaction that spends output 1), and reject the op otherwise. Alternatively, deprecate/gate the Bitcoin-op stacking path behind a requirement that the Stacks-side account also co-signs (e.g., require a matching Stacks transaction with the victim's signature) before `process_stacking_ops` treats `sender` as authorized.

### Proof of Concept
Rust integration test plan (mirroring existing `test_parse_pre_stack_stx`/`test_parse_stack_stx` in `stack_stx.rs`):
1. Build victim `StacksAddress` V and attacker keypair A (independent, unrelated hash160s).
2. Construct `BitcoinTransaction` for PreStxOp: input signed by A's key; `outputs[0].address` = V's hash160 (P2PKH); `outputs[1].address` = A's own address (to be spent later). Call `PreStxOp::parse_from_tx(...)` and assert `op.output == V`.
3. Construct a second `BitcoinTransaction` for StackStxOp spending `(prestx_txid, 1)`, signed only by A; `outputs[0].address` = A's reward address; opcode data encodes `stacked_ustx = victim_balance`. Call `StackStxOp::get_sender_txid` (assert it returns the PreStxOp's txid) then `StackStxOp::parse_from_tx(..., sender = &V, ...)` and assert `op.sender == V` and `op.reward_addr` corresponds to A.
4. Feed the resulting `StackStxOp` through `StacksChainState::process_stacking_ops` against a chainstate where V has a real unlocked STX balance and A has none stacked.
5. Assert (equality check both sides): before — `(stx-account V)` shows `locked = 0`; after — `(stx-account V)` shows `locked = stacked_ustx` and the pox reward-cycle entry for the reward cycle has `reward-addr = A`'s address, while no transaction signed by V's private key exists in the block. This demonstrates the locked-STX owner (V) diverges from the actual authorizing signer (A).

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

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L270-349)
```rust
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        epoch_id: StacksEpochId,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
        pox_sunset_ht: u64,
    ) -> Result<StackStxOp, op_error> {
        // can't be too careful...
        let num_outputs = tx.num_recipients();

        if tx.num_signers() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                num_outputs
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

        if tx.opcode() != Opcodes::StackStx as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = StackStxOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        let outputs = tx.get_recipients();
        assert!(!outputs.is_empty());

        let first_output = outputs
            .get(0)
            .ok_or_else(|| {
                warn!("Invalid tx: no first output");
                op_error::InvalidInput
            })?
            .as_ref()
            .ok_or_else(|| {
                warn!("Invalid tx: failed to decode first output");
                op_error::InvalidInput
            })?;

        // coerce a hash mode for this address if need be, since we'll need it when we feed this
        // address into the .pox contract
        let reward_addr = first_output.address.clone().coerce_hash_mode();

        // check if we've reached PoX disable
        if PoxConstants::has_pox_sunset(epoch_id) && block_height >= pox_sunset_ht {
            debug!(
                "StackStxOp broadcasted after sunset. Ignoring. txid={}",
                tx.txid()
            );
            return Err(op_error::InvalidInput);
        }

        Ok(StackStxOp {
            sender: sender.clone(),
            reward_addr,
            stacked_ustx: data.stacked_ustx,
            num_cycles: data.num_cycles,
            signer_key: data.signer_key,
            max_amount: data.max_amount,
            auth_id: data.auth_id,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
```

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L399-419)
```rust
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

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L591-607)
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

      ;; ensure that stacking can be performed
      (try! (can-stack-stx pox-addr amount-ustx first-reward-cycle lock-period))
```
