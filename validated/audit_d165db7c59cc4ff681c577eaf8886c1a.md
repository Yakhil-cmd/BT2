### Title
Unauthorized/Unsigned Stacking Lock via Unbound `sender` Field in `StackStxOp` - ([File: stackslib/src/chainstate/burn/operations/stack_stx.rs])

### Summary
`StackStxOp::parse_from_tx` sets the operation's `sender` field entirely from the previously-broadcast `PreStxOp.output`, a value the transaction author can set to any arbitrary Stacks address, with no cryptographic binding between that address and the private key that signs the Bitcoin inputs of either the `PreStxOp` or the `StackStxOp`. Because `process_stacking_ops` later executes `stack-stx` with `tx-sender = sender` directly, an attacker who fully controls both Bitcoin transactions (paying their own fees, signing their own inputs) can force any victim Stacks address with sufficient unlocked STX into an unsigned, involuntary stacking lock.

### Finding Description
The broken equality is: **AUTHORITY** — the principal whose STX gets locked by `stack-stx` (`tx-sender`) must equal a principal that cryptographically authorized the lock. Here, `sender` == victim B, but B never signed anything; the only authorizing signatures are the attacker's own Bitcoin keys on the `PreStxOp` and `StackStxOp` transactions.

Code path:
1. `PreStxOp::parse_from_tx` takes `output` purely from the first Bitcoin output address of the attacker's transaction — an arbitrary, attacker-chosen value with no relation to the input signer: [1](#0-0) 
2. `StackStxOp::get_sender_txid` only validates that the `StackStxOp`'s first input spends vout=1 of some prior `PreStxOp` txid — it never checks who authored that `PreStxOp` or whether its `output` field was chosen by/for the actual STX owner: [2](#0-1) 
3. `StackStxOp::parse_from_tx` takes `sender: &StacksAddress` as a parameter (ultimately `&pre_stack_stx.output`, wired up in `Burnchain::classify_transaction`) and stores it verbatim into the op with no further authorization check: [3](#0-2) 
4. `StacksChainState::process_stacking_ops` executes the pox contract's `stack-stx` with `tx-sender = sender.clone().into()` directly via `run_contract_call`, with no Stacks-level signature check at all: [4](#0-3) 
5. Inside `pox-4.clar`'s `stack-stx`, the only gating checks are that `tx-sender` (i.e., the attacker-chosen victim) is not already stacking/delegating and has sufficient unlocked STX balance, plus a signer-key signature that authorizes the *reward address/signer*, not the stacker: [5](#0-4) 

None of these steps verify that the Bitcoin key signing the `PreStxOp`/`StackStxOp` inputs corresponds to the Stacks address named in `output`/`sender`. The "same-key" assumption is a convention followed by honest wallets, not an enforced invariant.

### Impact Explanation
An unprivileged attacker (any BTC holder, no Stacks role required) can force-lock a victim's STX for up to `POX_MAX_NUM_CYCLES` reward cycles without the victim signing any transaction, provided the victim's address is unlocked, not already stacking/delegating, and holds the minimum stacking threshold. This is an "unsigned stacking action" causing temporary freezing of the victim's staked funds — matching the High-severity category. It does not enable theft of funds (STX unlocks automatically to the victim after the lock period and any PoX rewards accrue to the attacker-chosen reward address, not the victim's balance), so it is not Critical/fund theft, but it is a genuine denial-of-service / involuntary-lock griefing vector, repeatable against the same or different victims each time the target's STX becomes unlocked and idle.

### Likelihood Explanation
Feasible today with only two self-authored Bitcoin transactions (transaction fees are the only cost), no privileged role, and no cooperation from the victim required. The only preconditions are that the victim's address is unlocked, has ≥ minimum threshold STX, and is not currently stacking/delegating — public, observable on-chain information. This applies equally under the currently active `pox-4` (and would apply under `pox-5`, using the same `StackStxOp`/burnchain-op plumbing), so it is in-scope and not superseded.

### Recommendation
Require that the `sender`/`output` address used for burnchain-driven stacking ops be cryptographically tied to the key(s) signing the corresponding Bitcoin transaction (e.g., derive the Stacks address from the same public key that signs the `PreStxOp`/`StackStxOp` inputs, or require an explicit Stacks-side signature/authorization from the named `sender` before the contract-call is executed with their `tx-sender` identity), rather than trusting an arbitrary output field chosen unilaterally by the Bitcoin transaction author.

### Proof of Concept
Rust integration test (in the style of `stacks-node/src/tests/neon_integrations.rs`):
1. Create victim Stacks address B with STX balance ≥ minimum stacking threshold; B signs nothing.
2. Attacker (controls only their own Bitcoin key/UTXOs) submits `PreStxOp { output: B, .. }` on Bitcoin.
3. Attacker submits `StackStxOp` whose first input spends vout=1 of the `PreStxOp` txid, with attacker-chosen `stacked_ustx`, `num_cycles`, `reward_addr` (attacker's own PoX reward address), `signer_key`/`signer-sig` (attacker's own signer key/signature, valid for `consume-signer-key-authorization`).
4. Mine the burn block; process via `process_stacking_ops`.
5. Assert:
   - `op.sender == B` (violates: no signature from B was ever produced).
   - Query B's `STXBalance`/`stacking-state` in pox-4 and assert B's STX is now locked for the attacker-chosen `num_cycles`/`reward_addr`, despite B never issuing or signing a Stacks transaction — demonstrating LOCK without AUTHORITY.

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
