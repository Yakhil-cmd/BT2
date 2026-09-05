[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1213-1216)
```text
        (try! (verify-not-prepare-phase))

        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2404-2406)
```text
        (asserts! (not (var-get rewards-paused)) ERR_REWARDS_PAUSED)
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2449-2451)
```text
    (let ((rewards-info (settle-staker-rewards contract-caller reward-cycle bond-index staker)))
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))
```

**File:** contrib/core-contract-tests/tests/pox-5/pox-5-reentrancy.test.ts (L28-59)
```typescript
/**
 * A malicious signer whose validate-stake! re-enters pox-5 by calling
 * unstake-sbtc while the reentrancy guard is active. The guard should
 * propagate ERR_REENTRANT_CALL back through try!, causing
 * update-bond-registration to fail entirely with that error code.
 */
test('reentrancy via validate-stake! is blocked with ERR_REENTRANT_CALL', () => {
  const { signer: signer1 } = registerSigner({ caller: deployer });
  const signer1Name = testSigner.identifier.split('.')[1];

  const maliciousName = 'malicious-validate-signer';
  const maliciousId = `${deployer}.${maliciousName}`;

  // validate-stake! re-enters pox-5 by calling unstake-sbtc on Alice's
  // current signer (signer1). The guard is already set, so unstake-sbtc
  // immediately returns ERR_REENTRANT_CALL, which propagates via try!.
  //
  // It must re-enter the boot pox-5: the lock-aware instance the test drives,
  // on which update-bond-registration sets the guard. A bare `.pox-5` would
  // target the local instance, where Alice has no bond membership, so
  // unstake-sbtc returns ERR_NOT_BOND_PARTICIPANT before reaching the guard.
  const pox5Ref = `'${POX5_BOOT_ID}`;
  const maliciousSource = `\
(impl-trait ${pox5Ref}.signer-manager-trait)
(use-trait signer-manager-trait ${pox5Ref}.signer-manager-trait)
(define-public (validate-stake!
    (staker principal) (first-index uint) (num-indexes uint)
    (amount-ustx uint) (amount-sats uint) (is-bond bool)
    (signer-calldata (optional (buff 500))))
  (begin
    (try! (contract-call? ${pox5Ref} unstake-sbtc .${signer1Name} amount-sats))
    (ok true)))
```

**File:** contrib/core-contract-tests/tests/pox-5/pox-5-reentrancy.test.ts (L123-135)
```typescript
  const result = txErr(
    pox5.updateBondRegistration({
      signerManager: maliciousId,
      signerCalldata: null,
      oldSignerManager: signer1,
    }),
    alice,
  );

  expect(result.value).toBe(errorCodes.ERR_REENTRANT_CALL);
  // sBTC remains locked; Alice's balance is unchanged (not drained).
  expect(sbtcBalance(alice)).toBe(aliceBalanceLocked);
  expect(rov(pox5.getTotalSbtcStaked())).toBe(aliceSbtc);
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
