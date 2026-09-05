### Title
Unauthorized STX lock via burnchain `StackStxOp` using an attacker-forged `PreStxOp.output` address as the stacked account, with no Stacks-level signature check - (File: stackslib/src/chainstate/burn/operations/stack_stx.rs)

### Summary
`PreStxOp::parse_from_tx` derives `PreStxOp.output` solely from the first Bitcoin output's address of the pre-stx transaction, with no check that the broadcaster controls the corresponding Stacks private key. `StackStxOp::from_tx`/`parse_from_tx` then set `StackStxOp.sender` directly to that value, and `StacksChainState::process_stacking_ops` calls the PoX contract's `stack-stx` entry point using `sender.clone().into()` as `tx-sender`, so the STX-locking call executes as if the victim itself signed it.

### Finding Description
The broken equality is:
`StackStxOp.sender == StacksAddress whose private key authorized this stack-stx action` (AUTHORITY)

but the actual code only guarantees:
`StackStxOp.sender == whatever address the Bitcoin-transaction crafter wrote into vout[0] of the linked PreStxOp` (ARBITRARY STRING)

Code path:
1. `PreStxOp::parse_from_tx` extracts `output` from `outputs.get(0)` with no signature/authorization check against the tx's inputs: [1](#0-0) 
2. `StackStxOp::get_sender_txid` only enforces that the StackStxOp's Bitcoin input spends `vout == 1` of some prior transaction (presumed to be the PreStxOp) - it checks Bitcoin UTXO chain-of-custody, not any Stacks-key relationship to `output`: [2](#0-1) 
3. `StackStxOp::parse_from_tx` takes `sender: &StacksAddress` (resolved from the linked PreStxOp's `output`) and copies it verbatim into `StackStxOp.sender`: [3](#0-2) 
4. `StacksChainState::process_stacking_ops` then invokes the PoX contract's `stack-stx` with this `sender` as the Clarity `tx-sender`, i.e. as the account whose STX gets checked/locked: [4](#0-3) 
5. `stack-stx` in the active PoX contract only checks that `tx-sender` (i.e. the forged `sender`) is not already stacking/delegating and has sufficient unlocked balance - it never checks that `tx-sender` cryptographically authorized this specific call (only the *signer key* grant is separately verified, not the stacker's own consent): [5](#0-4) 

Exploit flow: the attacker (any unprivileged Bitcoin-funded actor) crafts and broadcasts a `PreStxOp` transaction whose first output pays an arbitrary victim `StacksAddress` (the victim need not sign or even know about this Bitcoin transaction). The attacker then spends `vout=1` of that transaction in a `StackStxOp` transaction with an attacker-chosen `stacked_ustx` amount and their own `reward_addr`/`signer_key`. Because `get_sender_txid` only verifies the UTXO link (not key ownership of `output`), the node accepts `StackStxOp.sender == victim`, and if the victim currently has sufficient unlocked STX and is not already stacking/delegating, the PoX contract call succeeds, locking the victim's STX for the requested cycles with rewards routed to the attacker's `reward_addr`.

No guard in the reviewed code paths (`stack_stx.rs`, `process_stacking_ops`, `pox-4.clar`'s `stack-stx`) verifies that the victim's private key authorized either the burnchain operation or the resulting Clarity call - the only "authorization" enforced is control of the Bitcoin UTXO chain from the PreStxOp to the StackStxOp, which is entirely within the attacker's control and unrelated to the victim's Stacks keys.

### Impact Explanation
An unprivileged attacker can force-lock any victim Stacks account's unlocked STX (up to its full unlocked balance) for up to `POX_MAX_NUM_CYCLES` reward cycles without the victim's Stacks-level signature, and redirect the resulting stacking rewards to the attacker's own `reward_addr`/`signer_key`. This is a temporary freeze of the victim's principal (returned automatically at unlock height) combined with theft of the rewards earned on that forcibly-locked principal for the duration - matching "theft ... of locked STX or sBTC rewards" and "an unsigned stacking action." The attack is repeatable against any victim address with sufficient idle balance and no pre-existing stacking/delegation state, each time the victim's balance is unlocked and eligible again.

### Likelihood Explanation
Preconditions are minimal and entirely attacker-controlled: the victim must simply hold enough unlocked STX and not currently be stacking or delegating - state that is public/observable on-chain. The attacker only needs to fund two small Bitcoin transactions (a `PreStxOp` and a chained `StackStxOp` spending its `vout=1`) with their own BTC, at any time, requiring no cooperation, signature, or awareness from the victim or any privileged role. This is highly feasible and cheap, and can be repeated across cycles.

### Recommendation
Require cryptographic proof that the `PreStxOp.output`/`StackStxOp.sender` address's private key authorized the stacking action - e.g., require a Stacks-level signature (analogous to the `signer-sig` mechanism already used for signer-key authorization) binding the designated stacker address to the specific `stacked_ustx`, `reward_addr`, and cycle parameters, verified before `process_stacking_ops` invokes `stack-stx` on the victim's behalf. Alternatively, restrict burnchain-op-based stacking so the "sender" must be independently verified against the input signer of the PreStxOp/StackStxOp chain rather than an arbitrary output address string.

### Proof of Concept
Rust integration test (pattern from `stackslib/src/chainstate/burn/operations/stack_stx.rs` tests and `stackslib/src/chainstate/coordinator/tests.rs`):
1. Boot a test chainstate; fund a "victim" Stacks address `V` with STX via genesis/initial balances, using a keypair the test never uses to sign anything.
2. Using an attacker-controlled Bitcoin wallet, craft a `PreStxOp` Bitcoin transaction whose first output (`vout=0`) pays `V`'s address; broadcast it.
3. Craft a `StackStxOp` Bitcoin transaction spending `vout=1` of the PreStxOp tx, with `parse_data` setting `stacked_ustx` to some amount `<=` `V`'s unlocked balance, and `reward_addr`/`signer_key` set to attacker-controlled values; broadcast it.
4. Mine/process the burn block so `StacksChainState::process_stacking_ops` runs.
5. Assert equality before: `V`'s `STXBalance` shows amount unlocked, `get-stacker-info(V)` is `none`.
6. Assert equality after: `get-stacker-info(V)` is `some` with `stacker == V` even though `V`'s private key never signed any transaction; `V`'s STX becomes locked; and the associated reward slot/`signer_key` correspond to attacker-controlled values - demonstrating `StackStxOp.sender == V` while `AUTHORITY(V's private key) == false`, confirming the equality break.

### Citations

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L109-126)
```rust
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
