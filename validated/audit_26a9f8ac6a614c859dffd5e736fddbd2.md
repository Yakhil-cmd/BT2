Confirmed: `PreStxOp.output` is simply the first Bitcoin output address of a PreStx transaction — output index 0 — with no requirement that this address correspond to the payer of the transaction's inputs. [1](#0-0)  Anyone who broadcasts a Bitcoin transaction can freely choose that output's address to be the victim's Stacks-equivalent address, since Bitcoin permits sending funds to any address regardless of who controls it.

However, the actual authority-granting step is `DelegateStxOp`, which is only accepted if its Bitcoin transaction's first input spends output index 1 of the specific `PreStxOp` transaction referenced by its `pre_stx_txid`. [2](#0-1)  The `sender` field of `DelegateStxOp` is not attacker-controlled data from the op payload — it is hard-set by the burnchain-op-linking logic in `Burnchain::check_transaction`/op-linking code to `pre_stx.output`, i.e., the address chosen in output 0 of the *matched* `PreStxOp`. [3](#0-2)  Critically, this `sender` value is later used as the literal Clarity `tx-sender` when the node calls `delegate-stx` on the pox contract on the delegator's behalf: `tx.run_contract_call(&sender.clone().into(), None, ..., "delegate-stx", ...)`. [4](#0-3)  This makes `DelegateStxOp.sender` — and therefore the party whose `delegation-state` is set — solely determined by the address string written into output 0 of the linked PreStxOp, with no Stacks-level signature check tying it to the victim's actual key.

The critical unresolved question is whether spending output 1 of the `PreStxOp` transaction to build the `DelegateStxOp` requires *Bitcoin* signing authority over that UTXO. `get_sender_txid` requires the DelegateStxOp's first input to be `(pre_stx_txid, vout=1)`. [2](#0-1)  Since the `PreStxOp` transaction itself is entirely attacker-crafted (the attacker chooses both outputs of the PreStx tx, using their own BTC inputs to fund it), the attacker who broadcasts the `PreStxOp` also creates output 1, and can then trivially spend that self-created output 1 (which they, not the victim, control the private key for) to build the follow-up `DelegateStxOp`. The victim's Stacks address is only referenced as the destination string of output 0 — a purely cosmetic/output field — not a UTXO the attacker needs to control cryptographically. The attacker never needs the victim's Bitcoin key at any point; they only need to write the victim's Stacks address bytes into the `PreStxOp` payload's output-0 address field, which is fully attacker-controlled since they construct that Bitcoin transaction themselves.

This means: `DelegateStxOp.sender` == the value the attacker chose to write as PreStxOp output 0 == an arbitrary Stacks address (e.g., the victim's), entirely decoupled from any Bitcoin or Stacks signature proving that address's owner authorized anything. The equality the question tests — "delegated authority recorded for a staker == authority that staker's Bitcoin-key-verified identity actually granted" — is broken: authority is recorded for `victim` (as `tx-sender` in `delegate-stx`) even though `victim` never signed, funded, or otherwise authorized any transaction. `DelegateStxOp::check()` performs no cross-check against the actual funder of the PreStxOp/DelegateStxOp chain, and there is no place downstream that verifies the "sender" identity against a Stacks-level signature at all — the entire burnchain-ops mechanism substitutes a raw Bitcoin address string for authenticated identity. [5](#0-4) 

That said, this only sets `delegation-state` for `victim` — a record permitting `delegate_to` (attacker) to *later* call `delegate-stack-stx`. The actual lock still requires: `(asserts! (>= (stx-get-balance stacker) amount-ustx) ...)` in pox-5/pox-4's `delegate-stack-stx`, checking `victim`'s real on-chain STX balance [6](#0-5) . If the attacker calls `delegate-stack-stx(stacker=victim, ...)` afterward, the pox contract will actually lock `victim`'s real STX under the attacker's chosen `pox-addr`, since `delegate-stack-stx` only checks `delegated-to == tx-sender` (the attacker) and `stacker`'s balance/PoX eligibility — never a victim-authored Stacks signature. [7](#0-6) 

### Title
Forged `PreStxOp`/`DelegateStxOp` pair allows an attacker to record and exercise stacking delegation authority over a victim's STX without any Stacks-level or Bitcoin-UTXO authorization from the victim - (File: `stackslib/src/chainstate/burn/operations/delegate_stx.rs`)

### Summary
`DelegateStxOp.sender` is derived purely from the destination address written into output 0 of the linked `PreStxOp` Bitcoin transaction, a field the attacker fully controls when crafting that transaction with their own BTC inputs. Because this `sender` value is later used verbatim as the Clarity `tx-sender` for the `delegate-stx` contract call, an attacker can set `sender` to a victim's Stacks address, causing pox-4/pox-5's `delegation-state` map to record a delegation from `victim` to `attacker` that the victim never authorized, which the attacker can later exploit via `delegate-stack-stx` to lock the victim's real STX balance under a pox-addr the attacker controls.

### Finding Description
The broken equality: `DelegateStxOp.sender` (used as `tx-sender` for `delegate-stx`) should equal the Bitcoin-key-verified identity that actually authorized the delegation; instead it equals an arbitrary address string chosen by whoever crafts the linked `PreStxOp`'s output 0, with no cryptographic tie to `victim`.

Path: attacker broadcasts `PreStxOp` (own BTC inputs) with output 0 = `victim_addr`, output 1 = attacker-controlled change [1](#0-0) . Attacker then broadcasts `DelegateStxOp` spending output 1 of that `PreStxOp` (which they control) with `delegate_to = attacker_addr`, `delegated_ustx` = victim's real balance [2](#0-1) . The burnchain op-linker sets `DelegateStxOp.sender = pre_stx.output = victim_addr` [3](#0-2) . `DelegateStxOp::check()` validates only `delegated_ustx != 0` and `until_burn_height` bounds — no balance or authorization check [5](#0-4) . `process_delegate_ops` then calls `delegate-stx` with `sender` (victim) as `tx-sender` [4](#0-3) , and pox's `delegate-stx` unconditionally writes `delegation-state{stacker: tx-sender} = {delegated-to: delegate-to, amount-ustx, ...}` [8](#0-7) .

Existing guards checked: `check-caller-allowed` only restricts *contract-callers*, not burnchain-op-driven direct calls (burnchain ops always call as if directly from `tx-sender`, bypassing this concern) — irrelevant here. `delegate-stack-stx` does check `stx-get-balance stacker >= amount-ustx` and `delegated-to == tx-sender`, meaning the STX lock still requires the victim to actually possess that balance, and the reward-pox-addr belongs to the attacker [9](#0-8) . No check anywhere validates that the entity named "sender" in `DelegateStxOp`/`PreStxOp` actually authorized the burnchain transaction via a Stacks signature — the entire model assumes possession of the *first* PreStxOp UTXO output substitutes for authentication, but that assumption is violated for output 0's address field, which is never a UTXO the spender needs to control.

### Impact Explanation
An attacker can force `victim`'s `delegation-state` to point at `attacker` as `delegated-to`, then invoke `delegate-stack-stx(stacker=victim, amount-ustx=<= victim balance>, pox-addr=<attacker-controlled>)`. This locks `victim`'s real, unconsented STX for the lock-period and directs the resulting reward payouts to a `pox-addr` the attacker/collaborator controls — this is theft of staking authority and diversion of PoX rewards away from the rightful staker, matching Critical: attacker gains signing/locking authority over a victim's STX without consent. It is repeatable against any victim address for the cost of two burnchain transactions (a PreStx + a DelegateStx), with the attacker paying only Bitcoin transaction fees.

### Likelihood Explanation
No privileged role or victim cooperation is required — the attacker only needs to craft two ordinary Bitcoin transactions using their own UTXOs, choosing an arbitrary destination string for PreStxOp output 0. This is feasible without needing the victim's Bitcoin or Stacks private key, low-cost (dust value + BTC fees), and fully repeatable for any victim/target amount up to victim's actual STX balance (the final lock is bounded by the real balance check in `delegate-stack-stx`, but the *delegation record* itself is fully forgeable regardless of the victim's balance).

### Recommendation
Require that `PreStxOp`'s output-0 address (used later as `DelegateStxOp.sender`/`StackStxOp.sender`/`TransferStxOp.sender`) be provably controlled by whoever signs the `PreStxOp`/follow-on transaction — e.g., by deriving `sender` from the actual input-signing key of the PreStx transaction (as is already conceptually intended for these ops) rather than trusting an arbitrary chosen output address, or by requiring pox-5/pox-4's `delegate-stx` and related Clarity entry points to additionally validate a Stacks-signed authorization message from the named stacker (similar to `consume-signer-key-authorization` for signer keys) before mutating `delegation-state`.

### Proof of Concept
Rust integration test plan (extending `stackslib/src/burnchains/tests/db.rs`'s DelegateStx tests):
1. Build a `PreStxOp` Bitcoin transaction with output 0 = `victim_addr` (arbitrary), output 1 = attacker-controlled address, funded entirely by attacker's own BTC inputs.
2. Build a `DelegateStxOp` Bitcoin transaction whose input spends `(pre_stx_txid, vout=1)` (i.e., spends the attacker-controlled output 1), with `delegate_to = attacker_addr`, `delegated_ustx = victim_real_balance`.
3. Feed both through `Burnchain::classify_ops`/op-linker and assert `DelegateStxOp.sender == victim_addr` (equality check: `sender` should equal a Bitcoin-key-verified identity, but here equals the arbitrary string).
4. Run `process_delegate_ops` against a chainstate where `victim_addr` holds real unlocked STX, and assert `delegation-state{stacker: victim_addr}.delegated-to == attacker_addr` is set with no victim signature ever produced.
5. Have attacker call `delegate-stack-stx(stacker=victim_addr, amount-ustx=victim_real_balance, pox-addr=attacker_pox_addr, ...)` and assert the lock succeeds, moving `victim`'s STX into a locked state controlled by `attacker`'s chosen reward address — violating the equality that delegated authority == victim-authorized authority.

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

**File:** stackslib/src/chainstate/burn/operations/delegate_stx.rs (L105-120)
```rust
    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!("Invalid tx: DelegateStxOp must spend the second output of the PreStxOp");
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: DelegateStxOp must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }
```

**File:** stackslib/src/chainstate/burn/operations/delegate_stx.rs (L207-225)
```rust
    pub fn check(&self) -> Result<(), op_error> {
        if self.delegated_ustx == 0 {
            warn!("Invalid DelegateStxOp, must have positive ustx");
            return Err(op_error::DelegateStxMustBePositive);
        }

        if let Some(height) = self.until_burn_height {
            if height > i64::MAX as u64 {
                warn!(
                    "Invalid DelegateStxOp: until_burn_height exceeds i64::MAX";
                    "until_burn_height" => height,
                    "txid" => %self.txid,
                );
                return Err(op_error::InvalidInput);
            }
        }

        Ok(())
    }
```

**File:** stackslib/src/burnchains/burnchain.rs (L964-991)
```rust
            x if x == Opcodes::DelegateStx as u8 => {
                let pre_stx_txid = DelegateStxOp::get_sender_txid(burn_tx).ok()?;
                let pre_stx_tx = match pre_stx_op_map.get(pre_stx_txid) {
                    Some(tx_ref) => Some(BlockstackOperationType::PreStx(tx_ref.clone())),
                    None => burnchain_db.find_burnchain_op(indexer, pre_stx_txid),
                };
                if let Some(BlockstackOperationType::PreStx(pre_stx)) = pre_stx_tx {
                    let sender = &pre_stx.output;
                    match DelegateStxOp::from_tx(block_header, burn_tx, sender) {
                        Ok(op) => Some(BlockstackOperationType::DelegateStx(op)),
                        Err(e) => {
                            warn!(
                                "Failed to parse delegate stx tx";
                                "txid" => %burn_tx.txid(),
                                "data" => %to_hex(&burn_tx.data()),
                                "error" => ?e,
                            );
                            None
                        }
                    }
                } else {
                    warn!(
                        "Failed to find corresponding input to DelegateStxOp";
                        "txid" => %burn_tx.txid().to_string(),
                        "pre_stx_txid" => %pre_stx_txid.to_string()
                    );
                    None
                }
```

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L4326-4341)
```rust
            let result = clarity_tx.connection().as_transaction(|tx| {
                tx.run_contract_call(
                    &sender.clone().into(),
                    None,
                    &boot_code_id(active_pox_contract, mainnet),
                    "delegate-stx",
                    &[
                        Value::UInt(*delegated_ustx),
                        Value::Principal(delegate_to.clone().into()),
                        until_burn_height_val,
                        reward_addr_val,
                    ],
                    |_, _| None,
                    &ResourceBudget::unlimited(),
                )
            });
```

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L642-685)
```text
(define-public (delegate-stx (amount-ustx uint)
                             (delegate-to principal)
                             (until-burn-ht (optional uint))
                             (pox-addr (optional { version: (buff 1), hashbytes: (buff 32) })))

    (begin
      ;; must be called directly by the tx-sender or by an allowed contract-caller
      (asserts! (check-caller-allowed)
                (err ERR_STACKING_PERMISSION_DENIED))

      ;; delegate-stx no longer requires the delegator to not currently
      ;; be stacking.
      ;; delegate-stack-* functions assert that
      ;; 1. users can't swim in two pools at the same time.
      ;; 2. users can't switch pools without cool down cycle.
      ;;    Other pool admins can't increase or extend.
      ;; 3. users can't join a pool while already directly stacking.

      ;; pox-addr, if given, must be valid
      (match pox-addr
         address
            (asserts! (check-pox-addr-version (get version address))
                (err ERR_STACKING_INVALID_POX_ADDRESS))
         true)

      (match pox-addr
         pox-tuple
            (asserts! (check-pox-addr-hashbytes (get version pox-tuple) (get hashbytes pox-tuple))
                (err ERR_STACKING_INVALID_POX_ADDRESS))
         true)

      ;; tx-sender must not be delegating
      (asserts! (is-none (get-check-delegation tx-sender))
        (err ERR_STACKING_ALREADY_DELEGATED))

      ;; add delegation record
      (map-set delegation-state
        { stacker: tx-sender }
        { amount-ustx: amount-ustx,
          delegated-to: delegate-to,
          until-burn-ht: until-burn-ht,
          pox-addr: pox-addr })

      (ok true)))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L957-1004)
```text
;; As a delegate, stack the given principal's STX using partial-stacked-by-cycle
;; Once the delegate has stacked > minimum, the delegate should call stack-aggregation-commit
(define-public (delegate-stack-stx (stacker principal)
                                   (amount-ustx uint)
                                   (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                   (start-burn-ht uint)
                                   (lock-period uint))
    ;; this stacker's first reward cycle is the _next_ reward cycle
    (let ((first-reward-cycle (+ u1 (current-pox-reward-cycle)))
          (specified-reward-cycle (+ u1 (burn-height-to-reward-cycle start-burn-ht)))
          (unlock-burn-height (reward-cycle-to-burn-height (+ (current-pox-reward-cycle) u1 lock-period))))
      ;; the start-burn-ht must result in the next reward cycle, do not allow stackers
      ;;  to "post-date" their `stack-stx` transaction
      (asserts! (is-eq first-reward-cycle specified-reward-cycle)
                (err ERR_INVALID_START_BURN_HEIGHT))

      ;; must be called directly by the tx-sender or by an allowed contract-caller
      (asserts! (check-caller-allowed)
        (err ERR_STACKING_PERMISSION_DENIED))

      ;; stacker must have delegated to the caller
      (let ((delegation-info (unwrap! (get-check-delegation stacker) (err ERR_STACKING_PERMISSION_DENIED))))
        ;; must have delegated to tx-sender
        (asserts! (is-eq (get delegated-to delegation-info) tx-sender)
                  (err ERR_STACKING_PERMISSION_DENIED))
        ;; must have delegated enough stx
        (asserts! (>= (get amount-ustx delegation-info) amount-ustx)
                  (err ERR_DELEGATION_TOO_MUCH_LOCKED))
        ;; if pox-addr is set, must be equal to pox-addr
        (asserts! (match (get pox-addr delegation-info)
                         specified-pox-addr (is-eq pox-addr specified-pox-addr)
                         true)
                  (err ERR_DELEGATION_POX_ADDR_REQUIRED))
        ;; delegation must not expire before lock period
        (asserts! (match (get until-burn-ht delegation-info)
                         until-burn-ht (>= until-burn-ht
                                           unlock-burn-height)
                      true)
                  (err ERR_DELEGATION_EXPIRES_DURING_LOCK))
        )

      ;; stacker principal must not be stacking
      (asserts! (is-none (get-stacker-info stacker))
        (err ERR_STACKING_ALREADY_STACKED))

      ;; the Stacker must have sufficient unlocked funds
      (asserts! (>= (stx-get-balance stacker) amount-ustx)
        (err ERR_STACKING_INSUFFICIENT_FUNDS))
```
