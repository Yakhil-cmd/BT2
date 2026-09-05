### Title
Unauthorised STX lock via forged `sender` in `StackStxOp`/`PreStxOp` burnchain path - (File: `stackslib/src/chainstate/burn/operations/stack_stx.rs`)

### Summary
`PreStxOp::parse_from_tx` derives the `output` field purely from the *address* of a Bitcoin transaction's first output, with no proof that whoever crafted the transaction controls the private key for that address. This attacker-chosen address becomes `StackStxOp.sender`, which is then used directly as the `tx-sender` executing pox-4's `stack-stx` Clarity function, locking that Stacks address's STX balance without any signature from that address's owner.

### Finding Description
The broken equality: `StackStxOp.sender` (the principal whose STX gets locked by `pox_lock_v4`) must equal a principal that cryptographically authorised the stacking action. In this codebase that equality is never enforced.

- `PreStxOp::parse_from_tx` takes `outputs.get(0)...address.try_into_stacks_address()` and stores it as `output`, with zero validation that the transaction signer (whoever supplies the BTC inputs) owns the private key behind that output address [1](#0-0) . Bitcoin outputs are freely choosable by the spender; only the *inputs* require a valid signature, so an attacker can set the first output's hash160 to be the victim's known Stacks-address hash160 while only signing with their own key.
- `Burnchain::classify_ops` finds the matching `PreStxOp` for a `StackStxOp` and sets `sender = &pre_stack_stx.output` directly, calling `StackStxOp::from_tx` with this attacker-nominated `sender` [2](#0-1) .
- `StackStxOp::check()` performs no identity/signature validation whatsoever on `sender` — it only checks `stacked_ustx != 0`, `num_cycles` bounds, and that an optional `signer_key` parses as a valid secp256k1 key [3](#0-2) . `SortitionHandleTx::check_transaction` calls exactly this `check()` and nothing more [4](#0-3) .
- `StacksChainState::process_stacking_ops` then runs the Clarity `stack-stx` contract call using `&sender.clone().into()` as the transaction principal — i.e., the *victim's* address becomes `tx-sender` inside pox-4.clar [5](#0-4) .
- Inside `pox-4.clar`'s `stack-stx`, all checks (`stx-get-balance tx-sender`, `get-stacker-info tx-sender`, delegation checks) operate on this attacker-chosen `tx-sender`, and `consume-signer-key-authorization` only validates that the nominated *signer* authorised this specific stacking action — it does **not** validate that the *stacker* (the victim) approved anything [6](#0-5) .
- The Rust-side lock is then applied unconditionally to the returned `stacker` principal via `pox_lock_v4`, which locks the victim's real STX balance [7](#0-6) .

The attacker's exact call sequence: craft a PreStx Bitcoin transaction whose first output's hash160 equals the victim's Stacks-address hash160 (attacker signs only with their own BTC key for the inputs); spend the PreStx tx's second output in a StackStxOp transaction encoding `stacked_ustx`, `num_cycles`, and an attacker-controlled `reward_addr`/`signer_key`. No existing guard (`check()`, `check_transaction`, `consume-signer-key-authorization`) verifies that the address nominated as `sender`/`stacker` ever signed a Bitcoin or Stacks transaction proving ownership.

### Impact Explanation
The victim's real, unlocked STX gets locked (`pox_lock_v4`) for `num_cycles` reward cycles under a signer key and reward address the victim never chose, while the attacker pays only Bitcoin transaction fees for two small transactions. If the attacker also nominates their own PoX reward address, they capture the reward-slot weight backed by the victim's locked STX. This is theft/frozen-value and an "unsigned stacking action" — matching the Critical impact category (unauthorized lock of a staker's funds, reward slot claimed by a non-owning party). It is repeatable against any Stacks holder whose C32 address hash160 the attacker knows (public information) as long as they hold sufficient unlocked STX and are not already stacking/delegating.

### Likelihood Explanation
Preconditions: victim has ≥ `stacked_ustx` unlocked STX and is not already in `stacking-state`/delegated; not post-PoX-sunset. Attacker needs only enough BTC to fund two burnchain-op transactions (PreStx + StackStx) and knowledge of the victim's public Stacks address (trivially obtainable). No privileged role, no miner/relayer collusion is required — purely a client-side Bitcoin-transaction-crafting attack, well within the "unprivileged attacker" threat model. Feasibility is high given the complete absence of ownership verification in `PreStxOp`/`StackStxOp::check()`.

### Recommendation
Require cryptographic proof that the party constructing the PreStx/StackStx pair controls the private key for the nominated `sender`/stacker address — e.g., require the PreStx transaction's first output to be spent (or otherwise proven) by the same key that signs the PreStx transaction's inputs, or require an accompanying Stacks-layer signature from the nominated stacker authorizing the burnchain-originated lock before `pox_lock_v4` is invoked.

### Proof of Concept
Rust integration test plan:
1. Set up a regtest chain with two BTC-funded keys: `attacker_btc_key` and a "victim" who only holds a Stacks account (no BTC needed for victim).
2. Compute `victim_stacks_addr` and derive a `BitcoinAddress` with the same hash160/version.
3. Using `bitcoin_regtest_controller`, submit a PreStx transaction signed by `attacker_btc_key` whose first output is `victim`-derived address (`PreStxOp::parse_from_tx` will set `output = victim_stacks_addr`), second output attacker-controlled.
4. Submit a StackStxOp transaction spending the PreStx tx's second output (vout=1), signed by `attacker_btc_key`, encoding `stacked_ustx`, `num_cycles`, attacker's `reward_addr`.
5. Mine blocks so `Burnchain::classify_ops`/`process_stacking_ops` runs.
6. Assert on both sides of the equality:
   - Before: `victim_stacks_addr` STX balance shows `locked == 0`.
   - After: `victim_stacks_addr` STX balance shows `locked == stacked_ustx`, `unlock_height` set, and the reward set entry for the relevant cycle references `reward_addr`/`signer_key` chosen by the attacker — while `victim` never signed any Bitcoin or Stacks transaction in the test.

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

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L398-419)
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
```

**File:** stackslib/src/burnchains/burnchain.rs (L929-936)
```rust
            x if x == Opcodes::StackStx as u8 => {
                let pre_stx_txid = StackStxOp::get_sender_txid(burn_tx).ok()?;
                let pre_stx_tx = match pre_stx_op_map.get(pre_stx_txid) {
                    Some(tx_ref) => Some(BlockstackOperationType::PreStx(tx_ref.clone())),
                    None => burnchain_db.find_burnchain_op(indexer, pre_stx_txid),
                };
                if let Some(BlockstackOperationType::PreStx(pre_stack_stx)) = pre_stx_tx {
                    let sender = &pre_stack_stx.output;
```

**File:** stackslib/src/chainstate/burn/db/processing.rs (L68-74)
```rust
            BlockstackOperationType::StackStx(ref op) => op.check().map_err(|e| {
                warn!(
                    "REJECTED({}) stack stx op {} at {},{}: {:?}",
                    op.block_height, &op.txid, op.block_height, op.vtxindex, &e
                );
                BurnchainError::OpError(e)
            }),
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

**File:** pox-locking/src/pox_4.rs (L178-223)
```rust
/// Handle responses from stack-stx and delegate-stack-stx in pox-4 -- functions that *lock up* STX
fn handle_stack_lockup_pox_v4(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, VmExecutionError> {
    debug!(
        "Handle special-case contract-call to {:?} {function_name} (which returned {value:?})",
        boot_code_id(POX_4_NAME, global_context.mainnet)
    );
    // applying a pox lock at this point is equivalent to evaluating a transfer
    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let (stacker, locked_amount, unlock_height) = match parse_pox_stacking_result(value) {
        Ok(x) => x,
        Err(_) => {
            // nothing to do -- the function failed
            return Ok(None);
        }
    };

    match pox_lock_v4(
        &mut global_context.database,
        &stacker,
        locked_amount,
        unlock_height,
    ) {
        Ok(_) => {
            // For direct stacking, we log the locked amount in the asset map.
            if function_name == "stack-stx" {
                global_context.log_stacking(&stacker, locked_amount)?;
            }

            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount,
                    unlock_height,
                    locked_address: stacker,
                    contract_identifier: boot_code_id(POX_4_NAME, global_context.mainnet),
                }));
            Ok(Some(event))
        }
```
