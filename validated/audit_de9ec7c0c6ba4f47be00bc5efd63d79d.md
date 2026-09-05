### Title
Unauthorized stacking of a victim's STX via a spoofed `PreStxOp.output` / `StackStxOp.sender` - (File: `stackslib/src/chainstate/burn/operations/stack_stx.rs`, `stackslib/src/burnchains/burnchain.rs`)

### Summary
`PreStxOp::parse_from_tx` takes the `sender`/`stacker` identity for all follow-up burnchain stacking ops purely from the first Bitcoin output of the `PreStx` transaction, with zero cryptographic link to whoever signs the transaction's inputs. [1](#0-0)  `Burnchain::classify_transaction` then feeds that unverified `pre_stx.output` directly in as `sender` for `StackStxOp`, `TransferStxOp`, and `DelegateStxOp`. [2](#0-1)  An attacker who funds/signs the Bitcoin inputs can nominate an arbitrary victim `StacksAddress` as the "stacker," and the PoX contract will lock the victim's real STX balance because `stack-stx` only checks `tx-sender`'s STX balance, not who submitted the underlying Bitcoin transaction.

### Finding Description
The broken equality is: **the Stacks account whose STX gets locked/committed by `stack-stx` MUST equal the account that economically funded/authorized the Bitcoin transaction that triggered the op.** Instead, `PreStxOp` records only `output` — the first output of the Bitcoin tx, decoded to a `StacksAddress` — with no requirement that this address be derived from, or otherwise tied to, the keys that signed the transaction's inputs: [1](#0-0) 

`Burnchain::classify_transaction` then binds this `output` as `sender` when parsing the paired `StackStxOp` (and `TransferStxOp`/`DelegateStxOp`), based solely on the follow-up tx's first input spending vout 1 of the `PreStx` tx (a Bitcoin-layer plumbing requirement, not an identity check): [2](#0-1) [3](#0-2) 

Finally, `process_stacking_ops` calls `run_contract_call` using `sender` (i.e. `pre_stx.output`) as the literal Clarity `tx-sender`: [4](#0-3) 

Inside `stack-stx` (pox-4/pox-5), the only ownership-related check is `(>= (stx-get-balance tx-sender) amount-ustx)`, plus `consume-signer-key-authorization`, which validates that the caller is authorized to use a given *signer key* — it does not validate that `tx-sender` (the victim) approved being staked at all: [5](#0-4) 

Attacker's exact call sequence:
1. Attacker builds a `PreStx` Bitcoin transaction with their own funded/signed input(s), and sets `output[0]` = victim's `StacksAddress`, `output[1]` = an attacker-controlled UTXO for chaining.
2. Attacker builds a `StackStx` Bitcoin transaction whose first input spends `output[1]` of the `PreStx` tx (satisfying `StackStxOp::get_sender_txid`'s `vout == 1` check), and sets its own output as `reward_addr` (their own PoX Bitcoin payout address).
3. On processing, `classify_transaction` binds `sender = victim's StacksAddress`, `reward_addr = attacker's BTC address`.
4. `process_stacking_ops` calls `stack-stx` with `tx-sender = victim`. If the victim's account had enough unlocked STX, is not already stacking/delegating, and (for pox-4/5) no signer-key mismatch occurs, the STX lock succeeds — locking the victim's own STX for the chosen `num_cycles`, while PoX Bitcoin rewards flow to the attacker's `reward_addr`.

Existing guards fail to prevent this because:
- `check-caller-allowed`/delegation checks only gate *contract-call* callers, not burnchain-op-driven stack-stx.
- `stx-get-balance tx-sender >= amount-ustx` verifies solvency, not consent.
- `consume-signer-key-authorization` authenticates the *signer key* owner, not the *stacker* (victim) — it proves nothing about whether the victim agreed to be the "stacker."
- No signature from the victim's Stacks key, nor any cryptographic tie between the Bitcoin input signer and `PreStxOp.output`, is ever checked anywhere in `parse_from_tx`/`classify_transaction`/`process_stacking_ops`.

### Impact Explanation
An attacker can force-lock any victim's unlocked STX balance for up to `POX_MAX_NUM_CYCLES` cycles without the victim's consent or Stacks-layer signature, while directing all resulting PoX Bitcoin rewards to an address the attacker controls. This is "temporary freezing of staked funds" belonging to a party who never authorized the stack — matching the High severity category ("temporary freezing of staked STX"). It is repeatable against any Stacks address with sufficient unlocked STX that is not already stacking/delegating, at the cost of two dust-value Bitcoin transactions per victim per stacking cycle.

### Likelihood Explanation
Preconditions: victim must have unlocked STX ≥ the amount the attacker specifies, must not already be `stack-stx`'d or delegating for that reward cycle, and (in pox-4/pox-5) the attacker must supply a valid signer key + authorization for that key (attacker's own signer key works fine, since the check validates the *signer key*, not the *victim*). Attacker cost is only dust BTC fees for two chained transactions; no privileged role or victim cooperation is needed. This is fully repeatable each reward cycle against any qualifying address, making it a realistic and low-cost attack vector, not merely theoretical — the mechanism (`PreStxOp.output` decoupled from Bitcoin-input identity) is exercised unconditionally by `classify_transaction` for every `StackStx`/`TransferStx`/`DelegateStx` op.

### Recommendation
Require that `PreStxOp.output` (and therefore the `sender`/`stacker` used for `StackStxOp`/`TransferStxOp`/`DelegateStxOp`) be cryptographically derivable from the same key(s) that signed the `PreStx` transaction's inputs (e.g., require the P2PKH/P2WPKH hash of the signing pubkey to match `output`), or alternatively require an explicit Stacks-layer signature/authorization from the nominated `sender`/`stacker` principal before `stack-stx`/`delegate-stx` locks its balance via a burnchain op.

### Proof of Concept
Rust integration test plan (in `stackslib/src/chainstate/stacks/boot/pox_5_tests.rs` or similar, following the pattern in `stackslib/src/burnchains/tests/db.rs`):
1. Create two keypairs: `attacker_btc_key` (funds/signs Bitcoin inputs) and derive `victim_stx_addr` independently (not from `attacker_btc_key`). Ensure `victim_stx_addr` has a known unlocked STX balance in genesis allocation.
2. Construct a `PreStxOp` with `output = victim_stx_addr`, signed/funded solely by `attacker_btc_key`.
3. Construct a `StackStxOp` Bitcoin tx spending vout 1 of the PreStx tx (also signed by `attacker_btc_key`), with `reward_addr` = attacker's own PoX address, `stacked_ustx` ≤ victim's balance.
4. Process both ops through `Burnchain::classify_transaction` → `StacksChainState::process_stacking_ops`.
5. Assert (both sides of the equality):
   - Before: `stx-get-balance(victim_stx_addr)` = full balance, unlocked; `stx-get-balance(attacker)` unaffected.
   - After: `get-stacker-info(victim_stx_addr)` is `Some`, `STXBalance` for `victim_stx_addr` shows `amount_locked = stacked_ustx`, `unlock_height` set — despite the victim never signing any Stacks transaction.
   - Confirm the PoX reward-cycle entry's `pox-addr` equals the attacker-controlled `reward_addr`, not any address belonging to the victim.
6. This demonstrates the STX debited/locked belongs to `victim_stx_addr` while the Bitcoin funding/signing and resulting reward benefit belong entirely to the attacker, confirming the broken equality.

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

**File:** stackslib/src/burnchains/burnchain.rs (L929-963)
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

**File:** contrib/boot-contracts-unit-tests/boot_contracts/pox-4.clar (L591-608)
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
