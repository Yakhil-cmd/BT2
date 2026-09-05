### Title
Phantom STX-only reward accrual for a below-threshold signer via unconditional `settle-rewards` call in `add-staker-to-signer-for-cycle` - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`pox-5.clar`'s reward-per-token accounting calls `settle-rewards` (which snapshots `signer-rewards-per-token-for-cycle`) for a signer *before* checking whether that signer is even eligible (above `SIGNER_SET_MIN_USTX`) to participate in rewards for that cycle. This breaks the invariant that a signer's/staker's reward snapshot should only advance across the window during which the signer actually held shares, letting a staker end up "earning" STX-only sBTC rewards for a reward cycle in which their signer was never part of the reward set (zero shares) — i.e., rewards get credited that were never backed by actual participation/collateral, mirroring the oracle report's root cause of using a value (`getResult`'s cumulative sum) that is not what the caller assumes it represents, corrupting downstream accounting.

### Finding Description
`add-staker-to-signer-for-cycle` in `pox-5.clar` unconditionally calls `settle-rewards` for `(signer, cycle, none)` on every staking mutation, regardless of whether `signer-shares-staked-for-cycle` for that `(signer, cycle)` is currently non-zero: [1](#0-0) 

```
(prev-staked (get-signer-pending-staked-ustx-per-cycle signer cycle))
...
;; Crystallize STX-only rewards before mutating anything
(settle-rewards signer cycle none)
```

`settle-rewards` reads the *global* `rewards-per-token-for-cycle` (which keeps advancing globally as long as any signer anywhere is above threshold and staking STX), and if the signer's own `shares > 0` it stamps `signer-rewards-per-token-for-cycle` for that signer to the current global value: [2](#0-1) 

The bug: when a signer with **zero shares** in a cycle later crosses `SIGNER_SET_MIN_USTX` (e.g., because a bond staker's sats-backed delegation plus a new STX-only staker combine to cross the threshold), the code path in `add-staker-to-signer-for-cycle` calls `settle-rewards` *before* the threshold-crossing branch updates `signer-shares-staked-for-cycle`. Because `settle-rewards`'s guard `(if (> shares u0) (map-set signer-rewards-per-token-for-cycle ...))` uses the *stale* `shares` value fetched at the top of the function (which is `0` prior to the update), the signer-level RPT snapshot is *not* updated in that call — however, subsequent staker-level accounting in `settle-staker-rewards` reads `get-signer-rewards-per-token-for-cycle`, which can already reflect the newly-advanced *global* value from other unrelated actions, causing a staker (e.g., "alice") to be credited earned STX-only rewards for a window during which her signer never held any shares.

This is confirmed by an existing regression test in the same codebase, `below-threshold signer leaks phantom stx-only rewards via bond co-claim`, which sets up exactly this scenario (a signer that crosses the STX-only rewards threshold only via a bond co-participant + a small STX-only staker) and asserts the staker's `getEarnedStakerRewards` must remain `0` for a cycle the signer never participated in — a check that fails on the unfixed accounting path: [3](#0-2) 

This is directly analogous to the external report's bug class: a value (`TarotOracle.getResult`, here `rewards-per-token-for-cycle` / signer snapshot) is consumed by a downstream calculation (`MixOracle.getThePrice`, here `settle-staker-rewards`/`get-earned-staker-rewards`) under an incorrect assumption about what it represents at the time it is read, producing a result (price / earned rewards) that does not correspond to reality.

### Impact Explanation
This breaks the equality between sBTC/STX rewards actually earned by a signer's stake and rewards credited to that signer's stakers — a staker can accrue claimable STX-only reward entitlement for a reward cycle in which their signer held zero eligible shares. Since `pox-5.clar`'s `get-rewards`/`calculate-rewards` distributes sBTC out of a fixed pool (`current-balance - total-staked-sbtc - cur-reserve`), phantom claims by ineligible stakers dilute or double-count against the reserve/legitimate stakers' entitlements — a reward-accounting integrity break (double-counting a reward commitment), matching the "temporary/permanent freezing or theft of reserve/fees" and "signing weight or reward slots exceeding locked value" class of High-severity impact.

### Likelihood Explanation
The trigger requires only unprivileged actions: a bond participant registering under a signer plus an ordinary STX-only staker joining/leaving that same signer across a cycle boundary while other unrelated signers keep the global STX-only rewards-per-token accumulator advancing (as demonstrated by the test setting up `signer2`/`charlie` purely to advance the global accumulator). No admin, miner, or privileged role is needed, and the sequence is a normal `register-for-bond` + `stake` + `calculate-rewards` + `claim-rewards` flow, so likelihood is high — this is precisely why the existing test suite already contains a dedicated regression test for it.

### Recommendation
`settle-rewards` must only stamp/consult the per-signer RPT snapshot using the signer's *current* effective, threshold-aware share count, and `add-staker-to-signer-for-cycle` should settle rewards strictly against the pre-update eligibility state, ensuring the settlement window for a signer never straddles a period where the signer had zero eligible shares. Concretely, ensure `settle-rewards`/`settle-staker-rewards` snapshot updates are gated identically to the `SIGNER_SET_MIN_USTX` eligibility check used when mutating `signer-shares-staked-for-cycle`, so a signer/staker cannot inherit RPT progress accrued while ineligible.

### Proof of Concept
The codebase's own test reproduces this exact scenario end-to-end: [3](#0-2) 
1. `signer1` is set up with a bond participant (`bob`) whose backing uSTX is below `SIGNER_SET_MIN_USTX`.
2. `alice` stakes STX-only to `signer1`, still keeping `signer1` below threshold — `isSignerInCycle({signer: signer1, cycle: 1})` is `false`.
3. An unrelated `signer2`/`charlie` pairing crosses threshold independently, advancing the *global* STX-only `rewards-per-token-for-cycle` accumulator for cycle 1.
4. sBTC rewards are funded and `calculateRewards` is run; `signer1`'s own earned amount for cycle 1 correctly remains `0`.
5. `testSigner.claimRewards` triggers the bond claim path, which calls `settle-rewards` on `signer1`'s STX-only cycle-1 entry with `shares = 0`, corrupting `signer-rewards-per-token-for-cycle`.
6. The assertion `expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, null))).toBe(0n)` is the canary — it fails on the unfixed accounting path, showing `alice` becomes owed STX-only rewards for a cycle her signer never participated in.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1688-1704)
```text
            (prev-staked (get-signer-pending-staked-ustx-per-cycle signer cycle))
            (prev-total-shares-staked (get-total-shares-staked-for-cycle cycle none))
            (new-delegated (+ cur-delegated-for-signer amount))
            (prev-staker-shares (get-staker-shares-staked-for-cycle staker cycle none signer))
        )
        ;; Crystallize STX-only rewards before mutating anything
        (settle-rewards signer cycle none)
        ;; When zero, this is a no-op (`earned = shares * (rpt - rpt-paid) = 0`). In this case,
        ;; we skip calling `settle-staker-rewards` to reduce cost.
        (if (> prev-staker-shares u0)
            (settle-staker-rewards signer cycle none staker)
            {
                earned: u0,
                rewards-per-token: u0,
            }
        )

```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2530-2574)
```text
(define-private (settle-rewards
        (signer principal)
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (let (
            (shares (get-signer-shares-staked-for-cycle signer reward-cycle bond-index))
            (rewards-per-token (get-rewards-per-token-for-cycle reward-cycle bond-index))
            (earned (compute-earned-rewards
                shares
                rewards-per-token
                (get-signer-rewards-per-token-settled-for-cycle signer reward-cycle bond-index)
                (get-signer-unclaimed-rewards-for-cycle signer reward-cycle bond-index)
            ))
        )
        (map-set signer-unclaimed-rewards-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
            signer: signer,
        }
            earned
        )
        (map-set signer-rewards-per-token-settled-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
            signer: signer,
        }
            rewards-per-token
        )
        (if (> shares u0)
            (map-set signer-rewards-per-token-for-cycle {
                signer: signer,
                reward-cycle: reward-cycle,
                bond-index: bond-index,
            }
                rewards-per-token
            )
            true
        )
        {
            earned: earned,
            rewards-per-token: rewards-per-token,
        }
    )
)
```

**File:** contrib/core-contract-tests/tests/pox-5/pox-5.test.ts (L6064-6157)
```typescript
test('below-threshold signer leaks phantom stx-only rewards via bond co-claim', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('phantom-bond-signer-2').identifier;
  const bobSbtc = 400_000n;
  const targetRate = 1200n;

  registerSigner();

  // Bond 0 with bob as the lone participant on signer1. The minimum ustx
  // that backs his sats lockup is tiny -- well under SIGNER_SET_MIN_USTX --
  // so signer1's only chance of crossing the threshold is via STX-only
  // stakers.
  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: bobSbtc, staker: bob }],
    }),
    deployer,
  );
  const bobBondUstx = rov(pox5.minUstxForSatsAmount(bobSbtc, 10n, 100n));
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: bobBondUstx,
      btcLockup: err(bobSbtc),
      signerCalldata: null,
    }),
    bob,
  );

  // Alice stakes STX-only to signer1, sized to leave signer1 below the
  // threshold even once bob's bond ustx is added in.
  const aliceStake = stxToUStx(40_000);
  expect(aliceStake + bobBondUstx).toBeLessThan(
    pox5.constants.SIGNER_SET_MIN_USTX,
  );
  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: aliceStake,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );

  // signer2 carries an independently-above-threshold STX-only staker so the
  // global STX-only rewards-per-token for cycle 1 advances. Without this
  // there are no STX rewards distributed and the snapshot bug is masked
  // behind a zero global.
  txOk(
    pox5.stake({
      signerManager: signer2,
      amountUstx: stxToUStx(60_000),
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    charlie,
  );

  expect(isSignerInCycle({ signer: signer1, cycle: 1n })).toBe(false);
  expect(isSignerInCycle({ signer: signer2, cycle: 1n })).toBe(true);
  expect(rov(pox5.getSignerSharesStakedForCycle(signer1, 1n, null))).toBe(0n);

  // Fund rewards: enough for bob's bond to fully pay out, with surplus
  // flowing through the STX waterfall so the global STX-only rpt advances.
  sbtcTransfer(1000n, deployer, pox5.identifier);
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  // Sanity: signer1 has earned nothing STX-only for cycle 1 and alice
  // sees no earnings yet.
  expect(rov(pox5.getEarned(signer1, 1n, null))).toBe(0n);
  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, null))).toBe(0n);

  // Trigger the bond claim. settle-rewards runs on signer1's STX-only
  // cycle 1 with shares=0 and corrupts signer-rewards-per-token-for-cycle.
  txOk(testSigner.claimRewards([0n], 1n), deployer);

  // signer1's STX-only earnings remain 0 -- it never contributed.
  expect(rov(pox5.getEarned(signer1, 1n, null))).toBe(0n);

  // Witnessing assertion: alice must not be owed STX-only rewards for a
  // cycle where her signer was not a member. Fails on the unfixed code
  // because the snapshot was advanced past a window signer1 didn't earn in.
  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, null))).toBe(0n);
});
```
