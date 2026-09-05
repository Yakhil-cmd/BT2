## Title
Forced, unsigned stacking of a victim's STX via decoupled `PreStxOp.output` / `StackStxOp.sender` on burnchain ops - ([File: stackslib/src/burnchains/burnchain.rs])

## Summary
`StackStxOp::from_tx` derives `sender` solely from `pre_stack_stx.output` (the first output of the referenced `PreStxOp`), while the requirement to invoke the follow-on `StackStxOp` is only that *some* input spends `vout=1` of that `PreStxOp` transaction. Nothing in `PreStxOp::parse_from_tx` or `StackStxOp::get_sender_txid`/`parse_from_tx` requires that the Bitcoin key controlling `vout=1` be the same key/address as `outputs[0]` (the address that becomes `sender`). This lets an attacker who fully controls both `vout=0`'s destination (arbitrary, permissionless) and `vout=1`'s destination (their own key) submit a `StackStxOp` that runs Clarity's `stack-stx` with `tx-sender` forged to an arbitrary victim address, with zero involvement or signature from the victim.

## Finding Description
The broken equality: **"`StackStxOp.sender` == an address that authorized `stacked_ustx`/`num_cycles`/`signer_key`/`reward_addr` for THIS transaction"** is assumed but never enforced. In reality `StackStxOp.sender` is set purely from `PreStxOp.output`: [1](#0-0) 

`PreStxOp::parse_from_tx` reads only `outputs[0]` to populate `output`, and never inspects or constrains `outputs[1]`: [2](#0-1) 

`StackStxOp::get_sender_txid` only checks that the StackStx transaction's input spends `vout == 1` of the referenced PreStx transaction - it does not check *who* signed that spend, nor that the spender's key corresponds to `outputs[0]`'s address: [3](#0-2) 

Because Bitcoin lets anyone create an output paying to *any* address (`outputs[0]`, i.e. the future "sender"/victim), while `outputs[1]` can be a completely different address that the attacker themselves controls, the attacker can:
1. Craft a `PreStxOp` transaction where `outputs[0]` = `victim_addr` (an address the attacker does not control on Stacks) and `outputs[1]` = an address the attacker controls.
2. Later spend `outputs[1]` (proving only that they control *that* key, unrelated to `victim_addr`) in a `StackStxOp` transaction whose OP_RETURN payload encodes attacker-chosen `stacked_ustx`, `num_cycles`, `signer_key`, `max_amount`, `auth_id`, and whose first output encodes an attacker-controlled `reward_addr`.
3. `burnchain.rs` resolves `sender = pre_stack_stx.output = victim_addr` and calls `StackStxOp::from_tx(..., sender, ...)`, producing a `StackStxOp{ sender: victim_addr, ... }`.

This op then feeds into `StacksChainState::process_stacking_ops`, which executes the Clarity `stack-stx` call **as `tx-sender = victim_addr`**: [4](#0-3) 

Inside `pox-4.clar`'s `stack-stx`, the only checks are that `victim_addr` has sufficient unlocked balance and isn't already stacking/delegating, plus `consume-signer-key-authorization`, which only validates that the attacker-chosen `signer-key` authorized the attacker-chosen `pox-addr`/period/amount - it says nothing about whether `victim_addr` (the stacker/tx-sender) consented: [5](#0-4) 

There is no signature field on `StackStxOp` binding the stacker's own consent (`sender` has no associated Stacks-level authorization), and the whole burn-op machinery treats "spent `vout=1`" as if it were proof that the entity is `pre_stack_stx.output`, which is false whenever the two outputs are deliberately decoupled.

None of the audit-listed guards (`verify-not-prepare-phase`, `check-pox-lock-period`, `verify-signer-key-grant`, `parse_pox_stake_result`) address this, because they all operate downstream of `tx-sender` already being forged to `victim_addr`; they validate stacking-mechanics, not stacker identity/consent.

## Impact Explanation
The attacker can force-lock any Stacks account with a spendable balance for up to `POX_MAX_NUM_CYCLES` cycles without that account's consent, and simultaneously direct the resulting PoX reward payout (`reward_addr`) and signer authority (`signer_key`) to themselves. Per-cycle this is:
- An unsigned stacking action against the victim (matches the High category "an unsigned stacking action").
- Temporary freezing of the victim's staked STX for the chosen `num_cycles` (matches "temporary freezing of staked funds", High).

This is repeatable against any address with unlocked STX and no active stacking/delegation state, at the cost of only Bitcoin transaction fees for the attacker (two small Bitcoin transactions). It does not require any privileged role, only ordinary control of Bitcoin funds/UTXOs, matching the unprivileged-attacker assumption of this audit.

## Likelihood Explanation
Preconditions are modest: victim must have an unlocked balance ≥ desired `stacked_ustx`, and not already be stacking/delegated in the target PoX contract (`pox-4`/`pox-5` if this burn-op path remains wired to them). No specific reward-cycle phase restriction is required beyond the ordinary sunset/epoch checks in `PreStxOp`/`StackStxOp` parsing. The attack requires zero cooperation or leaked keys from the victim - only knowledge of the victim's public Stacks address, which is by definition public. Feasibility is high and the attack is fully repeatable against many addresses in parallel, each attempt costing only Bitcoin fees.

## Recommendation
Require that the address spending `PreStxOp`'s `vout=1` cryptographically match (or explicitly authorize) `PreStxOp.output`/`StackStxOp.sender` before treating the `StackStxOp` as a valid stacking instruction for that sender - e.g., require `outputs[0]` and `outputs[1]` of the `PreStxOp` to share the same underlying key/hash160 (so that spending `vout=1` on Bitcoin necessarily proves control of the same key that determines `sender`), or otherwise reject `StackStxOp`s whose `pre_stack_stx.output`-derived Bitcoin address differs from the scriptPubKey/address actually controlling `vout=1`.

## Proof of Concept
Rust integration test plan (analogous to `stackslib/src/burnchains/tests/db.rs` patterns and `stackslib/src/chainstate/coordinator/tests.rs`):
1. Create `victim_addr` (a `StacksAddress` for which the test does **not** hold any private/burnchain key), and give it a funded, unlocked STX balance in genesis/chainstate.
2. Construct a `PreStxOp`/`BitcoinTransaction` with `outputs[0].address` = the Bitcoin address corresponding to `victim_addr`'s hash160, and `outputs[1].address` = an address controlled by the attacker's own test keypair.
3. Confirm the `PreStxOp` via `burnchain_db`/sortdb as in `burnchains/tests/db.rs`.
4. Craft a `StackStxOp` Bitcoin transaction whose sole input spends `vout=1` of the `PreStxOp` tx (signed with the attacker's own key), with OP_RETURN payload encoding attacker-chosen `stacked_ustx`, `num_cycles`, `signer_key` (attacker's own), and first output = attacker-controlled `reward_addr`.
5. Run through `burnchain.rs`'s `StackStx` branch and assert the resulting `BlockstackOperationType::StackStx(op).sender == victim_addr`.
6. Feed the op through `StacksChainState::process_stacking_ops` against `pox-4.clar` and assert:
   - Before: `victim_addr`'s `STXBalance` shows `locked == 0`.
   - After: `victim_addr`'s `STXBalance` shows `locked == stacked_ustx` and `unlock_height` set per attacker-chosen `num_cycles`, with `stacking-state` for `victim_addr` populated - despite `victim_addr` never signing any Stacks transaction and the private key never being used.
7. Assert the equality violation directly: `StackStxOp.sender == victim_addr` while `victim_addr`'s Stacks-level authorization (signature) for `stacked_ustx`/`num_cycles`/`signer_key` is absent - the only "authorization" present is the attacker's Bitcoin signature over an unrelated key (`outputs[1]`).

### Citations

**File:** stackslib/src/burnchains/burnchain.rs (L929-944)
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
```

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

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L587-607)
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

      ;; Validate ownership of the given signer key
      (try! (consume-signer-key-authorization pox-addr (- first-reward-cycle u1) "stack-stx" lock-period signer-sig signer-key amount-ustx max-amount auth-id))

      ;; ensure that stacking can be performed
      (try! (can-stack-stx pox-addr amount-ustx first-reward-cycle lock-period))
```
