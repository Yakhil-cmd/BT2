Based on my investigation, I found a boundary-condition asymmetry in `pox-5.clar` that structurally mirrors the reported bug class (two different "sides" treating the same period boundary inconsistently, letting an actor act on the more permissive side while the other side hasn't actually reached the equivalent state).

### Title
Rollover-window boundary inconsistency between `verify-bond-rollover-window` (`>=`) and the actual bond/L1-unlock semantics could allow a bond rollover before L1 collateral is truly free - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`verify-bond-rollover-window` gates `register-for-bond` / `stake` rollovers on `burn-block-height >= (get-bond-l1-unlock-height existing-bond)` [1](#0-0)  while other boundary predicates in the same contract, such as `is-bond-active-at-height`, use strict `>` for the analogous "has this period truly started/ended" check [2](#0-1) . This is the same class of "different inequality on the boundary block" defect as the fork-DAO report, but I was not able to fully confirm end-to-end exploitability.

### Finding Description
The rollover gate opens exactly at `get-bond-l1-unlock-height(old-bond)`, using `>=`, meaning the very block at that height already permits registering into a new bond and rolling the STX lock forward [3](#0-2) . Meanwhile, `is-bond-active-at-height` — used elsewhere to determine whether a bond period is "live" at a given height — treats the bond's start boundary with strict `>`, i.e., asymmetric with the `<=` used for its end boundary [4](#0-3) . `register-for-bond` itself gates the *new* bond's start with strict `<` (`burn-block-height < bond-start-height`) [5](#0-4) .

For a true theft/unbacked-mint analog akin to the fork-DAO bug, the exploitable gap would need to be: the on-chain Bitcoin L1 timelock (CLTV script built by `construct-lockup-output-script`) matures at a different exact block than the Clarity-side `get-bond-l1-unlock-height` boundary used by `verify-bond-rollover-window`, such that a staker could register for the *new* bond (crediting new sats/shares) via `>=` while their original L1 BTC lockup script is *not yet* actually spendable/unlocked on Bitcoin (i.e., a `>` vs `>=` mismatch between the Clarity gate and the L1 script's real CLTV height) — or conversely, could reuse the same still-locked L1 proof to register into a second bond before the first bond's position is fully retired. I located `construct-lockup-output-script`/`construct-lockup-script` and `verify-l1-lockups`/`validate-l1-lockup`-style logic referenced in tests [6](#0-5) , but ran out of iterations before I could pull the exact CLTV-height derivation and the L1-lockup-outpoint dedup/consumption logic inside `pox-5.clar` to confirm whether the boundary is actually inconsistent between the Bitcoin script and the Clarity check, or whether the `>=`/`<`/`<=` choices here are all deliberately and correctly complementary (which the accompanying test suite — e.g. `register-for-bond rejects a rollover attempt before the old bond's L1 unlock window` [7](#0-6)  and `register-for-bond is rejected with ERR_STAKE_IN_PREPARE_PHASE inside the bond's prepare phase` [8](#0-7)  — strongly suggests, since these boundaries appear to have been deliberately tested at exact block granularity).

### Impact Explanation
If the L1-unlock-window Clarity check (`>=`) is looser by one block than the actual Bitcoin CLTV maturity the L1 lockup script enforces, a staker could register into a new bond (receiving reward-share credit / rolling sBTC forward) one block before their original BTC collateral is genuinely spendable-unlockable, which is a temporary double-counting of a commitment. This would be a High-severity issue per the rubric (signing weight/reward slots exceeding locked value) if confirmed. However, I could not confirm the actual CLTV height computation in this session, so this remains unverified.

### Likelihood Explanation
Low-to-uncertain: this requires precise, deliberate timing of a transaction at an exact block height, similar to the original report's "coordinate to land in a specific block" scenario. Given the extensive dedicated test coverage of exactly this boundary (`mineUntil(bond0L1Unlock - 1n)` / `mineUntil(bond0L1Unlock)` patterns [9](#0-8) ), it is plausible the boundary has already been hardened correctly and no exploitable gap actually exists.

### Recommendation
Verify that the exact block height at which the Bitcoin CLTV script inside `construct-lockup-output-script`/`construct-lockup-script` becomes spendable is identical (not off-by-one) to the height returned by `get-bond-l1-unlock-height`, and that `verify-bond-rollover-window`'s `>=` comparison is consistent with `is-bond-active-at-height`'s `>` / `<=` split and with `register-for-bond`'s `<` gate on `bond-start-height`. Add an explicit unit test that stands up the real Bitcoin timelock script and confirms rollover eligibility in Clarity and spendability on Bitcoin change at the exact same absolute block.

### Proof of Concept
Not constructed — this requires reading the exact CLTV-height derivation inside `pox-5.clar` (`construct-lockup-output-script`, `construct-lockup-script`, `verify-l1-lockups`) and the Bitcoin script encoding to determine whether an actual off-by-one exists between the L1 maturity height and `get-bond-l1-unlock-height`. I was unable to retrieve those definitions before running out of tool iterations, so I cannot confirm this is a real (as opposed to merely structurally similar) vulnerability.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L721-724)
```text
        ;; Verify that the bond hasn't started
        (asserts! (< burn-block-height bond-start-height)
            ERR_BOND_ALREADY_STARTED
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L3009-3024)
```text
(define-private (verify-bond-rollover-window (existing-membership (optional {
    bond-index: uint,
    amount-ustx: uint,
    signer: principal,
    is-l1-lock: bool,
    amount-sats: uint,
})))
    (ok (asserts!
        (match existing-membership
            existing (>= burn-block-height
                (get-bond-l1-unlock-height (get bond-index existing))
            )
            true
        )
        ERR_ROLLOVER_TOO_EARLY
    ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L3027-3040)
```text
(define-read-only (is-bond-active-at-height
        (bond-index uint)
        (calculation-height uint)
    )
    (let (
            (bond-start-height (bond-period-to-burn-height bond-index))
            (bond-end-height (bond-period-to-burn-height (+ bond-index u6)))
        )
        (and
            (is-some (map-get? protocol-bonds bond-index))
            (> calculation-height bond-start-height)
            (<= calculation-height bond-end-height)
        )
    )
```

**File:** stacks-node/src/tests/pox_5_integrations.rs (L1699-1735)
```rust
    // (a) Compute the expected P2WSH script-pubkey by calling pox-5's own
    //     read-only `construct-lockup-output-script` — this returns `(ok ...)`
    //     with the 34-byte `0x0020 || sha256(timelock_script)` that the
    //     burn-chain output must pay to. We hand the same arguments the
    //     contract will reconstruct internally during `verify-l1-lockups`.
    let bond_index = 0u128;
    let minimum_unlock_burn_height = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "get-bond-l1-unlock-height",
        vec![&Value::UInt(bond_index)],
    )
    .result()
    .expect("get-bond-l1-unlock-height failed")
    .expect_u128()
    .expect("get-bond-l1-unlock-height should return a uint");
    let unlock_burn_height = minimum_unlock_burn_height + 1;
    let expected_script_buff = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "construct-lockup-output-script",
        vec![
            &Value::Principal(staker_addr.clone().into()),
            &Value::UInt(unlock_burn_height),
            &Value::buff_from(lockup_unlock_bytes.clone()).unwrap(),
            &Value::buff_from(early_unlock_bytes.clone()).unwrap(),
        ],
    )
    .result()
    .expect("construct-lockup-output-script failed")
    .expect_result_ok()
    .expect("construct-lockup-output-script should return (ok ...)")
    .expect_buff(34)
    .expect("construct-lockup-output-script should return (buff 34)");
    assert_eq!(
```

**File:** contrib/core-contract-tests/tests/pox-5/pox-5.test.ts (L5269-5346)
```typescript
/**
 * A rollover attempted before the old bond's L1 collateral would have
 * unlocked must be rejected. The rollover window opens at
 * `(get-bond-l1-unlock-height old)` (half a cycle before the old bond's end).
 */
test("register-for-bond rejects a rollover attempt before the old bond's L1 unlock window", () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const sbtcAmount = 5000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  // One block before bond 0's L1 unlock — still inside the old bond's term,
  // outside the rollover window. Bond 6's setup window has opened (cycles
  // C+10..C+12), so this is a real "too-early" rollover, not blocked by
  // `setup-bond` timing.
  const bond0L1Unlock = rov(pox5.getBondL1UnlockHeight(0n));
  mineUntil(bond0L1Unlock - 1n);

  txOk(
    pox5.setupBond({
      bondIndex: 6n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );

  const tooEarly = txErr(
    pox5.registerForBond({
      bondIndex: 6n,
      signerManager: signer,
      amountUstx: rov(
        pox5.minUstxForSatsAmount(sbtcAmount, stxValueRatio, minUstxRatio),
      ),
      btcLockup: err(sbtcAmount),
      signerCalldata: null,
    }),
    alice,
  );
  expect(tooEarly.value).toEqual(pox5Errors.ERR_ROLLOVER_TOO_EARLY);

  // One block later — inside the L1 unlock window — the same call now
  // succeeds, confirming the gate opens exactly at the L1 unlock height.
  mineUntil(bond0L1Unlock);
  registerSbtcBondWithMinStx({
    bondIndex: 6n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });
  expect(rov(pox5.getBondMembership(alice))!.bondIndex).toBe(6n);
});
```

**File:** contrib/core-contract-tests/tests/pox-5/pox-5.test.ts (L5741-5809)
```typescript
/**
 * The L1-unlock-window check and the prepare-phase check overlap toward the
 * very end of the bond's last cycle: the prepare phase begins inside the
 * rollover window. A `register-for-bond` issued inside both must surface as
 * `ERR_STAKE_IN_PREPARE_PHASE`, not as `ok` (and not as
 * `ERR_ROLLOVER_TOO_EARLY` since we're past the L1 unlock).
 */
test("register-for-bond is rejected with ERR_STAKE_IN_PREPARE_PHASE inside the bond's prepare phase", () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const sbtcAmount = 5000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  // Bond 6 setup must happen before we enter cycle 12's prepare phase,
  // since `setup-bond` runs no prepare-phase gate but `register-for-bond`
  // does. Run setup while still well inside the L1 window.
  mineUntil(rov(pox5.getBondL1UnlockHeight(0n)));
  txOk(
    pox5.setupBond({
      bondIndex: 6n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );

  // Mine into cycle 12's prepare phase. Still inside the L1 window
  // (`>= getBondL1UnlockHeight(0)`) and bond 6 hasn't started yet
  // (`< bondPeriodToBurnHeight(6)`), so neither the rollover-window gate nor
  // `ERR_BOND_ALREADY_STARTED` fires — only the prepare-phase gate should.
  mineUntil(rov(pox5.bondPeriodToBurnHeight(6n)) - 5n);
  const inPrepare = txErr(
    pox5.registerForBond({
      bondIndex: 6n,
      signerManager: signer,
      amountUstx: rov(
        pox5.minUstxForSatsAmount(sbtcAmount, stxValueRatio, minUstxRatio),
      ),
      btcLockup: err(sbtcAmount),
      signerCalldata: null,
    }),
    alice,
  );
  expect(inPrepare.value).toEqual(pox5Errors.ERR_STAKE_IN_PREPARE_PHASE);
});
```
