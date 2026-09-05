### Title
Unsigned STX lock via forged `PreStxOp` output — attacker locks a victim's STX and steals PoX rewards - ([File: stackslib/src/chainstate/burn/operations/stack_stx.rs])

### Summary
`PreStxOp::parse_from_tx` sets `PreStxOp.output` (the future `StackStxOp.sender`) directly from Bitcoin output[0]'s address, with no check that the same key that signed the transaction's inputs controls that address. Because sending BTC to an address requires no cooperation from the address owner, an attacker can name any victim's `StacksAddress` as `output[0]`, spend `output[1]` themselves in a subsequent `StackStxOp`, and cause `stack-stx` in `pox-4.clar` to lock the victim's unlocked STX and pay PoX rewards to an attacker-controlled Bitcoin address — with zero involvement or signature from the victim.

### Finding Description
The broken equality: **STX locked by the applied `stack-stx` call == STX owned by the party who authorized (signed) the operation**. In the current code, the "sender"/`tx-sender` used to lock funds is derived purely from an unauthenticated Bitcoin output address, not from the key that signed the spending input.

Trace:
1. `PreStxOp::parse_from_tx` (stackslib/src/chainstate/burn/operations/stack_stx.rs:74-144) takes `outputs.get(0)` — the Bitcoin transaction's first recipient — and converts its address directly into `PreStxOp.output` via `try_into_stacks_address()`, with no relation whatsoever to `tx.get_signers()`/the input keys. [1](#0-0) 
2. `StackStxOp::get_sender_txid` only verifies that the `StackStxOp`'s input spends **vout 1** of the referenced `PreStxOp` tx — it performs no check that the signer of that input is related to `PreStxOp.output` (i.e., output[0]). [2](#0-1) 
3. `Burnchain::classify_transaction` resolves the `sender` for the `StackStxOp` purely as `&pre_stack_stx.output` (the forged victim address) and passes it into `StackStxOp::from_tx`/`parse_from_tx`, which stores it as `StackStxOp.sender` unconditionally. [3](#0-2) [4](#0-3) 
4. `StacksChainState::process_stacking_ops` runs the `stack-stx` contract call with `tx-sender` set to `sender.clone().into()` — the forged/victim address — with args (`signer_key`, `max_amount`, `auth_id`) taken entirely from the OP_RETURN payload that the attacker controls, and `signer-sig` forced to `none`. [5](#0-4) [6](#0-5) 
5. `pox-4.clar`'s `stack-stx` checks only that `tx-sender` has sufficient unlocked balance and is not already stacking/delegating — it never validates that `tx-sender` authorized the call; that authorization is implicitly assumed to come from the fact that a normal Stacks transaction is signed by `tx-sender`'s key. For burnchain ops this assumption is false because `tx-sender` here is attacker-supplied. [7](#0-6) 
6. `consume-signer-key-authorization`/`verify-signer-key-sig` only validate the *signer key* (pool signer identity for the reward slot), which is unrelated to `tx-sender`'s ownership of the locked STX — when `signer-sig` is `none`, it merely checks a pre-existing authorization map entry, which is irrelevant to whether `tx-sender` consented. [8](#0-7) 

No code path checks that the Bitcoin input key that signs the `StackStxOp`'s spending transaction matches the `PreStxOp.output` Stacks address (which would require them to be the same Hash160/pubkey). This linkage is simply assumed by the design (P2PKH "sender = self" convention) but is never enforced.

### Impact Explanation
The attacker can force-lock any known Stacks address's unlocked STX balance into PoX stacking for up to `POX_MAX_NUM_CYCLES` reward cycles, directing the resulting PoX Bitcoin rewards to a reward address of their own choosing (also encoded in the same operation), while providing a `signer_key` of their choosing. This is:
- An **unsigned stacking action** — the victim's STX are locked without any signature from the victim's Stacks key.
- **Temporary freezing of staked funds** — the victim's STX are locked for the chosen `num_cycles` and cannot be used/transferred until unlock, without consent.
- Diversion of the associated PoX Bitcoin reward stream to the attacker's chosen reward address, even though the locked principal belongs to the victim.

Per the severity taxonomy given, this matches the **High** category ("temporary freezing of staked funds", "an unsigned stacking action") rather than Critical, since the STX principal is not permanently stolen — it unlocks back to the victim's account after the lock period. It is repeatable against any address with sufficient unlocked balance and not currently stacking/delegating, at the cost of two cheap Bitcoin transactions per victim per attempt.

### Likelihood Explanation
Preconditions are minimal and fully attacker-controlled:
- Attacker needs any BTC UTXO (their own) and knowledge of the victim's Stacks address (public information).
- Victim only needs unlocked STX ≥ the amount the attacker chooses, and to not already be stacking/delegating (a state easily observed on-chain).
- No PoX cycle-phase restriction beyond the normal `stack-stx` window (`start-burn-ht` must equal the next reward cycle), which the attacker fully controls since they craft the transaction.
- No privileged role is required at all — the attacker only broadcasts two ordinary Bitcoin transactions.
This is highly feasible and repeatable against any number of victims.

### Recommendation
Require that the `PreStxOp` output (`output[0]`) can be cryptographically tied to the actual signer of the transaction's input(s) — e.g., require `output[0]`'s Hash160 to match the Hash160 of the public key used to sign the `PreStxOp`'s (or the subsequent `StackStxOp`'s) first input, or otherwise require the burnchain `sender` field to be authenticated by the same key that signs the spending input in `StackStxOp`. Alternatively, require a corresponding signed Stacks-chain authorization (similar to `signer-key-authorizations`) from the `sender` principal before `process_stacking_ops` is permitted to lock funds on their behalf.

### Proof of Concept
Rust integration test plan (extends existing tests in `stack_stx.rs`):
1. Build a `BitcoinTransaction` for `PreStxOp` where `outputs[0].address` = `victim_hash160` (arbitrary, attacker does not hold the corresponding private key) and `outputs[1].address` = `attacker_hash160` (attacker-controlled), with input(s) signed only by the attacker's key.
2. Call `PreStxOp::parse_from_tx(...)` and assert `op.output == StacksAddress::from_legacy_bitcoin_address(victim_hash160)`.
3. Build a second `BitcoinTransaction` for `StackStxOp` whose input spends vout 1 of the prior tx (attacker-signed), and call `StackStxOp::get_sender_txid` / `StackStxOp::parse_from_tx(..., sender = &pre_stx.output, ...)`; assert `op.sender == victim_addr`.
4. Feed both ops through `Burnchain::classify_transaction` and `StacksChainState::process_stacking_ops` against a test chainstate where `victim_addr` has unlocked STX ≥ `stacked_ustx`.
5. Before: `stx-account victim_addr` unlocked-balance = X, locked = 0. After: assert locked = `stacked_ustx`, unlocked = X - `stacked_ustx`, `reward_addr` == attacker's chosen address — all without any Stacks transaction signed by `victim_addr`'s key ever appearing in the mempool/chainstate.

Note: due to index size limits, the exact `Burnchain::classify_transaction` full function body and `StacksChainState::process_stacking_ops` calling context around epoch gating were only partially inspected; a full reproduction should be validated in a live Devin session with complete file access to confirm no additional un-cited guard exists elsewhere in the burnchain-op ingestion pipeline (e.g., in `sortdb` or op ordering logic) that might restrict this path further.

### Citations

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L106-127)
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

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L337-349)
```rust
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

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L4097-4130)
```rust
            let mut args = vec![
                Value::UInt(*stacked_ustx),
                // this .expect() should be unreachable since we coerce the hash mode when
                // we parse the StackStxOp from a burnchain transaction
                reward_addr
                    .as_clarity_tuple()
                    .expect("FATAL: stack-stx operation has no hash mode")
                    .into(),
                Value::UInt(u128::from(*block_height)),
                Value::UInt(u128::from(*num_cycles)),
            ];
            // Appending additional signer related arguments for pox-4
            if active_pox_contract == PoxVersions::Pox4.get_name() {
                match StacksChainState::collect_pox_4_stacking_args(&stack_stx_op) {
                    Ok(pox_4_args) => {
                        args.extend(pox_4_args);
                    }
                    Err(e) => {
                        warn!("Skipping StackStx operation for txid: {}, burn_block: {} because of failure in collecting pox-4 stacking args: {}", txid, burn_header_hash, e);
                        continue;
                    }
                }
            }
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

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L4192-4219)
```rust
    pub fn collect_pox_4_stacking_args(op: &StackStxOp) -> Result<Vec<Value>, String> {
        let signer_key = match &op.signer_key {
            Some(signer_key) => match Value::buff_from(signer_key.as_bytes().to_vec()) {
                Ok(signer_key) => signer_key,
                Err(_) => {
                    return Err("Invalid signer_key".into());
                }
            },
            _ => return Err("Invalid signer key".into()),
        };

        let max_amount_value = match op.max_amount {
            Some(max_amount) => Value::UInt(max_amount),
            None => return Err("Missing max_amount".into()),
        };

        let auth_id_value = match op.auth_id {
            Some(auth_id) => Value::UInt(u128::from(auth_id)),
            None => return Err("Missing auth_id".into()),
        };

        Ok(vec![
            Value::none(),
            signer_key,
            max_amount_value,
            auth_id_value,
        ])
    }
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

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L735-762)
```text
(define-read-only (verify-signer-key-sig (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                         (reward-cycle uint)
                                         (topic (string-ascii 14))
                                         (period uint)
                                         (signer-sig-opt (optional (buff 65)))
                                         (signer-key (buff 33))
                                         (amount uint)
                                         (max-amount uint)
                                         (auth-id uint))
  (begin
    ;; Validate that amount is less than or equal to `max-amount`
    (asserts! (>= max-amount amount) (err ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH))
    (asserts! (is-none (map-get? used-signer-key-authorizations { signer-key: signer-key, reward-cycle: reward-cycle, topic: topic, period: period, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount }))
              (err ERR_SIGNER_AUTH_USED))
    (match signer-sig-opt
      ;; `signer-sig` is present, verify the signature
      signer-sig (ok (asserts!
        (is-eq
          (unwrap! (secp256k1-recover?
            (get-signer-key-message-hash pox-addr reward-cycle topic period max-amount auth-id)
            signer-sig) (err ERR_INVALID_SIGNATURE_RECOVER))
          signer-key)
        (err ERR_INVALID_SIGNATURE_PUBKEY)))
      ;; `signer-sig` is not present, verify that an authorization was previously added for this key
      (ok (asserts! (default-to false (map-get? signer-key-authorizations
            { signer-key: signer-key, reward-cycle: reward-cycle, period: period, topic: topic, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount }))
          (err ERR_NOT_ALLOWED)))
    ))
```
