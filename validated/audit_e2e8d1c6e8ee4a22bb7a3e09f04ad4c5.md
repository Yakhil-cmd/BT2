[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** pox-locking/src/pox_5.rs (L360-395)
```rust
/// Handle responses from pox-5 entry points that lock STX for a staker:
/// `stake` (STX-only) and `register-for-bond` (protocol bond). A first-time
/// call (no existing pox-5 lock) acquires a fresh lock via
/// [`pox_lock_v5`]; a roll-over (the account is already locked from an
/// ending bond or stake) carries the lock forward via
/// [`pox_rollover_v5`] -- the amount may go up or down and the
/// unlock height is rescheduled, so the lock never releases. The contract
/// is responsible for gating the roll-over (non-overlap + L1 unlock window
/// for bond sources); if the contract returns ok, this handler trusts the
/// call is legitimate.
fn handle_lockup_pox_v5(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, VmExecutionError> {
    debug!(
        "Handle special-case contract-call to {:?} {function_name} (which returned {value:?})",
        boot_code_id(POX_5_NAME, global_context.mainnet)
    );
    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let parsed = parse_pox_stake_result(value).map_err(|e| {
        locking_error_to_vm_error(e, &format!("pox-5 {function_name}: bad response"))
    })?;
    let (staker, locked_amount, unlock_height) = match parsed {
        ParsedStakeResult::Ok {
            staker,
            amount_ustx,
            unlock_burn_height,
        } => (staker, amount_ustx, unlock_burn_height),
        ParsedStakeResult::ContractErr => return Ok(None),
    };
```

**File:** pox-locking/src/pox_5.rs (L443-471)
```rust
/// Handle responses from `stake-update` in pox-5 -- the function that
/// *extends or increases already-locked* STX.
fn handle_stake_lockup_update_pox_v5(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, VmExecutionError> {
    debug!(
        "Handle special-case contract-call to {:?} {function_name} (which returned {value:?})",
        boot_code_id(POX_5_NAME, global_context.mainnet),
    );

    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let parsed = parse_pox_stake_result(value).map_err(|e| {
        locking_error_to_vm_error(e, &format!("pox-5 {function_name}: bad response"))
    })?;
    let (staker, amount_ustx, unlock_height) = match parsed {
        ParsedStakeResult::Ok {
            staker,
            amount_ustx,
            unlock_burn_height,
        } => (staker, amount_ustx, unlock_burn_height),
        ParsedStakeResult::ContractErr => return Ok(None),
    };
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2387-2420)
```text
(define-public (claim-rewards
        (bond-periods (list 6 uint))
        (reward-cycle uint)
    )
    (let (
            (signer contract-caller)
            (stx-rewards (update-claimable-rewards signer reward-cycle none))
            (bond-rewards (fold update-claimable-bond-rewards bond-periods {
                signer: signer,
                total: u0,
                bond-rewards: (list),
                reward-cycle: reward-cycle,
            }))
            (bond-totals (get total bond-rewards))
            (total-rewards (+ (get earned stx-rewards) bond-totals))
            (prev-accrued-rewards (var-get last-accounted-rewards-only))
        )
        (asserts! (not (var-get rewards-paused)) ERR_REWARDS_PAUSED)
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        (asserts! (> total-rewards u0) ERR_NO_CLAIMABLE_REWARDS)
        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" total-rewards
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer total-rewards tx-sender signer none
            ))
        ))
        ;; Update contract reward snapshot to prevent issues in next calculation
        (var-set last-accounted-rewards-only
            (- prev-accrued-rewards total-rewards)
        )
```

**File:** contrib/core-contract-tests/tests/pox-5/pox-5.test.ts (L4117-4159)
```typescript
test('zero reward claim should not reset paid rewards', () => {
  const signer = testSigner.identifier;
  const stakeAmount = stxToUStx(50_000);

  registerSigner();

  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stakeAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1000n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([]), deployer);

  const expectedRewards = stxRewards(1000n);
  expect(rov(pox5.getEarned(signer, 1n, null))).toBe(expectedRewards);
  const claim = txOk(testSigner.claimRewards([], 1n), deployer);
  const [ftTransfer] = filterEvents(
    claim.events,
    CoreNodeEventType.FtTransferEvent,
  );
  expect(ftTransfer.data.sender).toBe(pox5.identifier);
  expect(ftTransfer.data.recipient).toBe(signer);
  expect(ftTransfer.data.amount).toBe(expectedRewards.toString());

  const zeroClaim = txErr(testSigner.claimRewards([], 1n), deployer);
  expect(zeroClaim.value).toBe(errorCodes.ERR_NO_CLAIMABLE_REWARDS);
});
```
