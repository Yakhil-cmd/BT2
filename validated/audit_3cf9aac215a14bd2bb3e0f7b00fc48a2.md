### Title
Delegate can lock a stacker's STX via `delegate-stack-stx` while never calling `stack-aggregation-commit`, permanently withholding the reward-cycle commitment and freezing the stacker's funds for the full lock period - (File: `stackslib/src/chainstate/stacks/boot/pox-4.clar`)

### Summary
In pox-4, `delegate-stack-stx` immediately produces a lock-up instruction that the node executes (locking the stacker's STX for the whole `lock-period`), but it only records the stacked amount as *partial* — the pox address is not yet in any reward-cycle's slot list. Getting an actual reward slot (and thus any signing weight / stacking reward) requires the delegate to separately call `stack-aggregation-commit`/`stack-aggregation-commit-indexed` before the cycle's PoX anchor block. Nothing forces the delegate to do this. A delegate can call `delegate-stack-stx` (locking the stacker's funds) and simply never call the commit function, so the stacker's STX stay locked for the entire cycle(s) while never being counted toward any reward set — exactly analogous to the VRF admin starting a raffle but withholding the step that lets it actually pay out.

### Finding Description
`delegate-stack-stx` in [1](#0-0)  validates the delegation, then calls `add-pox-partial-stacked` (which only updates the `partial-stacked-by-cycle` map) and sets `stacking-state` with an **empty** `reward-set-indexes: (list)`. It then returns `{ stacker, lock-amount, unlock-burn-height }` — the lock-up info that the Stacks node uses to actually lock the STX.

That lock-up info is consumed by the pox-locking layer: [2](#0-1)  parses the response and calls `pox_lock_v4`, applying the STX lock to the stacker's account and emitting an `STXLockEvent` — this happens for `delegate-stack-stx` exactly as it does for `stack-stx`, per the dispatch in [3](#0-2) . So the stacker's funds are locked at this point regardless of whether the pox-address ever gets a reward-cycle slot.

The only way that partial stake is turned into an actual reward-cycle commitment (a slot in `reward-cycle-pox-address-list`, contributing to signer weight and stacking rewards) is via `inner-stack-aggregation-commit`, invoked through `stack-aggregation-commit`/`stack-aggregation-commit-indexed`: [4](#0-3) . This call must be made by the delegate before the reward cycle's PoX anchor block, is fully separate from `delegate-stack-stx`, and no contract logic requires it to ever happen.

Consequently, a delegate can:
1. Call `delegate-stack-stx` for a stacker who delegated to them (locking that stacker's STX for the entire committed `lock-period`, exactly as `stack-stx` would).
2. Never call `stack-aggregation-commit`/`stack-aggregation-commit-indexed` for that reward cycle.

The stacker's STX remains locked until `unlock-burn-height` (computed and fixed at `delegate-stack-stx` time), but the pox-address never appears in `reward-cycle-pox-address-list`, so the stacker earns zero signing weight and zero stacking rewards for the locked period, and has no in-protocol mechanism to force the commit or to unlock early. This breaks the equality "STX locked for stacking == STX actually counted toward a reward-cycle commitment," the same equality the VRFNFTRandomDraw report identifies (funds/actions "started" without ever completing the step that pays out).

### Impact Explanation
This is a temporary freezing of staked STX: the victim's funds are locked by the delegate's own transaction, and the victim receives none of the reward-cycle benefits the lock was for, for the entire committed `lock-period`. Per the rules, temporary freezing of staked funds is a High-impact class.

### Likelihood Explanation
Any principal that has been delegated to (via `delegate-stx`, a normal step in pool-based stacking) can trigger this by simply omitting a step they already have full unilateral control over (`stack-aggregation-commit`). No special/admin privileges are required — only being the designated delegate, which is the standard trust relationship in delegated stacking. A malicious, buggy, or unresponsive pool operator can do this to any/all of its delegators, and there's no check elsewhere in `pox-4.clar` that forces the commit step, nor a way for the affected stacker to unwind the lock early.

### Recommendation
- Require the reward-cycle commitment (`stack-aggregation-commit`) to be an atomic part of `delegate-stack-stx`'s effect, or make the STX lock conditional on the commit having succeeded (e.g., defer the actual `pox_lock_v4` invocation/lock-up instruction until the aggregation commit occurs, rather than at `delegate-stack-stx` time).
- Alternatively, expose an on-chain refund/early-unlock path for stackers whose partially-stacked funds were never committed to a reward-cycle slot before the cycle's anchor block, so the lock does not silently persist for the full period with no reward.
- At minimum, add an explicit read-only check/event so delegators can detect (before the prepare phase ends) whether their delegate failed to commit, and document/alert on this trust assumption.

### Proof of Concept
1. Stacker `S` calls `delegate-stx` to delegate `amount-ustx` to pool operator `D`.
2. `D` calls `delegate-stack-stx(S, amount-ustx, pox-addr, start-burn-ht, lock-period)` — pox-4.clar returns `(ok { stacker: S, lock-amount, unlock-burn-height })`, which the pox-locking handler (`handle_stack_lockup_pox_v4`) uses to lock `S`'s STX for `lock-period` cycles (`pox-locking/src/pox_4.rs:178-222`).
3. `D` never calls `stack-aggregation-commit` / `stack-aggregation-commit-indexed` for that reward cycle before the PoX anchor block.
4. Result: `S`'s STX remains locked until `unlock-burn-height`, but `S`'s pox-address never enters `reward-cycle-pox-address-list` for any cycle in `[first-reward-cycle, first-reward-cycle+lock-period)`, so `S` earns no signing weight or rewards for funds that were fully locked.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L802-841)
```text
(define-private (inner-stack-aggregation-commit (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                                (reward-cycle uint)
                                                (signer-sig (optional (buff 65)))
                                                (signer-key (buff 33))
                                                (max-amount uint)
                                                (auth-id uint))
  (let ((partial-stacked
         ;; fetch the partial commitments
         (unwrap! (map-get? partial-stacked-by-cycle { pox-addr: pox-addr, sender: tx-sender, reward-cycle: reward-cycle })
                  (err ERR_STACKING_NO_SUCH_PRINCIPAL))))
    ;; must be called directly by the tx-sender or by an allowed contract-caller
    (asserts! (check-caller-allowed)
              (err ERR_STACKING_PERMISSION_DENIED))
    (let ((amount-ustx (get stacked-amount partial-stacked)))
      (try! (consume-signer-key-authorization pox-addr reward-cycle "agg-commit" u1 signer-sig signer-key amount-ustx max-amount auth-id))
      (try! (can-stack-stx pox-addr amount-ustx reward-cycle u1))
      ;; Add the pox addr to the reward cycle, and extract the index of the PoX address
      ;; so the delegator can later use it to call stack-aggregation-increase.
      (let ((add-pox-addr-info
                (add-pox-addr-to-ith-reward-cycle
                   u0
                   { pox-addr: pox-addr,
                     first-reward-cycle: reward-cycle,
                     num-cycles: u1,
                     reward-set-indexes: (list),
                     stacker: none,
                     signer: signer-key,
                     amount-ustx: amount-ustx,
                     i: u0 }))
           (pox-addr-index (unwrap-panic
                (element-at (get reward-set-indexes add-pox-addr-info) u0))))

        ;; don't update the stacking-state map,
        ;;  because it _already has_ this stacker's state
        ;; don't lock the STX, because the STX is already locked
        ;;
        ;; clear the partial-stacked state, and log it
        (map-delete partial-stacked-by-cycle { pox-addr: pox-addr, sender: tx-sender, reward-cycle: reward-cycle })
        (map-set logged-partial-stacked-by-cycle { pox-addr: pox-addr, sender: tx-sender, reward-cycle: reward-cycle } partial-stacked)
        (ok pox-addr-index)))))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L957-1025)
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

      ;; ensure that stacking can be performed
      (try! (minimal-can-stack-stx pox-addr amount-ustx first-reward-cycle lock-period))

      ;; register the PoX address with the amount stacked via partial stacking
      ;;   before it can be included in the reward set, this must be committed!
      (add-pox-partial-stacked pox-addr first-reward-cycle lock-period amount-ustx)

      ;; add stacker record
      (map-set stacking-state
        { stacker: stacker }
        { pox-addr: pox-addr,
          first-reward-cycle: first-reward-cycle,
          reward-set-indexes: (list),
          lock-period: lock-period,
          delegated-to: (some tx-sender) })

      ;; return the lock-up information, so the node can actually carry out the lock.
      (ok { stacker: stacker,
            lock-amount: amount-ustx,
            unlock-burn-height: unlock-burn-height })))
```

**File:** pox-locking/src/pox_4.rs (L178-222)
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
```

**File:** pox-locking/src/pox_4.rs (L414-423)
```rust
    // Execute function specific logic to complete the lock-up
    let lock_event_opt = if function_name == "stack-stx" || function_name == "delegate-stack-stx" {
        handle_stack_lockup_pox_v4(global_context, function_name, value)?
    } else if function_name == "stack-extend" || function_name == "delegate-stack-extend" {
        handle_stack_lockup_extension_pox_v4(global_context, function_name, value)?
    } else if function_name == "stack-increase" || function_name == "delegate-stack-increase" {
        handle_stack_lockup_increase_pox_v4(global_context, function_name, value)?
    } else {
        None
    };
```
