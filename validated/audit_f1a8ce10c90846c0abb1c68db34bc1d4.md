### Title
`PreStxOp::output` and `StackStxOp::sender` are never bound to the signer of the underlying Bitcoin transaction, allowing any account to lock a victim's STX and redirect PoX rewards to itself - ([File: stackslib/src/chainstate/burn/operations/stack_stx.rs])

### Summary
`PreStxOp::parse_from_tx` derives the "stacker" identity solely from the first Bitcoin *output* of the attacker-crafted PreStxOp transaction, with no check that this output corresponds to a Bitcoin key the attacker (or anyone else who actually signed the funding transaction) controls. `burnchain.rs` then propagates that unverified address as `sender` into `StackStxOp`, and `process_stacking_ops` in `blocks.rs` calls `stack-stx` with that address hard-wired as `tx-sender`, bypassing any Stacks-transaction-level signature check.

### Finding Description
The broken equality: "STX locked by an applied `stack-stx` burn op == STX owned by the address that cryptographically authorized the lock" is violated. In practice the equality that holds is only "STX locked == STX owned by whatever address the attacker wrote into `output`" — no cryptographic binding to that address's private key is ever checked.

Code path:
1. `PreStxOp::parse_from_tx` takes `outputs.get(0)` — an output address the *attacker themselves writes* into their own Bitcoin transaction — and decodes it via `try_into_stacks_address()` into `PreStxOp.output`, with zero validation against the transaction's inputs/signers: [1](#0-0) 
2. When the follow-up `StackStxOp` transaction (spending `vout=1` of the PreStxOp) is classified, `burnchain.rs` binds `sender = &pre_stack_stx.output` directly and feeds it into `StackStxOp::from_tx`: [2](#0-1) 
3. `StackStxOp::parse_from_tx` stores that unverified `sender` verbatim in the resulting op: [3](#0-2) 
4. `process_stacking_ops` executes the Clarity `stack-stx` call with `&sender.clone().into()` as the raw contract-call sender — this is a direct VM injection of `tx-sender`, not a signature-checked Stacks transaction: [4](#0-3) 
5. `pox-4.clar`'s `stack-stx` only checks that `tx-sender` (the injected victim address) has sufficient unlocked balance and isn't already stacking/delegating — it performs no check that the party submitting the burn op actually controls that principal: [5](#0-4) 

Exploit flow: an attacker funds and signs a Bitcoin transaction entirely with their own UTXOs, writing the victim's known Stacks-mapped Bitcoin address as the first output (`PreStxOp.output`). They then spend `vout=1` of that transaction themselves (satisfying `get_input_tx_ref(0)==(txid,1)` in `StackStxOp::get_sender_txid`), embedding an attacker-chosen `reward_addr` (the BTC address that receives PoX rewards) and a `signer_key`/`signer-sig` that only needs to authorize a signer key for the specified `pox-addr` — not to prove ownership of the victim's principal. Provided the victim has spendable STX and no `stacking-state` entry, `stack-stx` succeeds with `tx-sender = victim`, locking the victim's STX for `num_cycles` while rewards flow to the attacker's chosen `reward_addr`.

None of the existing guards (`check-caller-allowed`, `get-stacker-info`, `get-check-delegation`, `stx-get-balance`, `consume-signer-key-authorization`) verify that the entity submitting the burn ops is the same entity that controls `sender`'s private key — they only validate the signer-key/pox-addr binding and balance sufficiency, not the stacker's authorization to be locked at all.

### Impact Explanation
The victim's STX is locked for the chosen `lock-period` without their consent (an unsigned stacking action), and the PoX BTC reward stream tied to that locked STX is redirected to an attacker-controlled `reward_addr`. This is repeatable against any address with spendable STX and no existing stacking-state, at the cost of Bitcoin transaction fees only. This matches the "High — an unsigned stacking action" / temporary freezing of staked funds category; it also results in theft of the reward stream that should have accrued to the STX owner.

### Likelihood Explanation
Preconditions are minimal and fully attacker-controlled: the victim need only hold spendable STX and not currently be in `stacking-state`/delegating — conditions any active Stacks holder frequently satisfies. The attacker needs no privileged role, only their own Bitcoin UTXOs and Stacks/Bitcoin key material, matching the allowed "unprivileged attacker" profile (crafting burnchain ops from their own Bitcoin inputs). The attack is cheap (Bitcoin transaction fees) and repeatable across cycles and victims.

### Recommendation
Require cryptographic proof that the entity submitting the `PreStxOp`/`StackStxOp` pair controls the `output`/`sender` Stacks address — e.g., require the PreStxOp's first Bitcoin input's public key to hash to the same address as `output`, or require an accompanying Stacks-style signature from `sender` authorizing the specific `stacked_ustx`/`num_cycles`/`reward_addr` parameters before `process_stacking_ops` injects `sender` as `tx-sender`.

### Proof of Concept
Rust integration test (extending `stackslib/src/burnchains/tests/db.rs` patterns / `stack_stx.rs` unit tests):
1. Generate victim keypair `V` and derive its Stacks/Bitcoin addresses; fund `V`'s Stacks address with STX via genesis/coinbase so it has spendable balance and no `stacking-state`.
2. As attacker `A` (separate keypair, own BTC UTXOs), construct and sign a Bitcoin transaction with opcode `PreStx`, output[0] = `V`'s Bitcoin-mapped address, output[1] = spendable by `A`.
3. As `A`, spend output[1] of that transaction in a new Bitcoin transaction with opcode `StackStx`, embedding attacker-chosen `reward_addr`, `stacked_ustx`, `num_cycles`, and a `signer_key`/`signer-sig` for a signer key `A` controls.
4. Submit both to a booted chainstate (`process_stacking_ops` via `setup_block`/`append_block`).
5. Assert: `get-stacker-info V` returns `Some` with `pox-addr == A`'s `reward_addr`, and `V`'s account balance reflects the STX as locked — despite no transaction ever having been signed with `V`'s private key. Assert on both sides of the equality: "STX locked belongs to `V`" (true) vs "the lock was authorized by `V`" (false, since only `A`'s signatures appear anywhere in the transaction chain).

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

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L591-604)
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
