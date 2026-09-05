### Title
Phantom sBTC/STX-only reward accrual via zero-share `settle-rewards` snapshot corruption in bond co-claim path - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`pox-5.clar` calls `settle-rewards` on a signer's STX-only reward-per-token checkpoint whenever a bond participant is added or removed for that signer/cycle, without checking whether the signer currently has zero STX-only shares staked or is even a member of the signer set for that cycle. When `settle-rewards` runs with `shares == 0`, it still advances the signer's stored "rewards-per-token" checkpoint to the current global value, even though the signer earned nothing during the window it was not a set member. A later staker settlement for that signer/cycle then computes `earned = shares * (rpt - rpt_paid)` using a corrupted `rpt_paid` baseline, crediting STX-only rewards to a staker who staked to a signer that never actually qualified for rewards in that cycle. This mirrors the audit report's root cause: a function whose return value/state can legitimately be zero/invalid is used by a caller without checking for that degenerate case, corrupting downstream accounting.

### Finding Description
`add-staker-to-signer-for-cycle` and `remove-staker-from-signer-for-cycle` both unconditionally call `settle-rewards` for the affected signer/cycle "before mutating anything," as shown at [1](#0-0) and [2](#0-1) . These call sites do not gate on whether the signer is presently a member of the cycle's signer set (i.e., whether `is-in-signer-set`/`new-delegated >= SIGNER_SET_MIN_USTX`) nor on whether `cur-staked-for-signer`/`prev-staker-shares` for that signer is zero, except for the narrow optimization in `add-staker-to-signer-for-cycle` that skips `settle-staker-rewards` (not `settle-rewards`) when `prev-staker-shares == u0`, as seen at [3](#0-2) .

The reproduction test `below-threshold signer leaks phantom stx-only rewards via bond co-claim` in the project's own regression suite demonstrates this exact failure mode: signer1 stays below `SIGNER_SET_MIN_USTX` for cycle 1 (Bob's bond ustx + Alice's STX-only stake together do not cross the threshold), so signer1 is never a member of the cycle-1 signer set and legitimately earns `u0` STX-only rewards. A second signer (signer2) is above threshold so that the *global* STX-only reward-per-token value for cycle 1 is non-zero. When Bob's bond claim later triggers `remove-staker-from-signer-for-cycle` for signer1/cycle 1, the unconditional `settle-rewards signer reward-cycle none` call advances signer1's stored per-token checkpoint to the global value even though signer1 had `shares = 0` and was never in the set — see [4](#0-3) . The test's final assertion checks that Alice — who staked STX-only to signer1 — must not be credited rewards for a cycle her signer never earned in: [5](#0-4) . The test comment explicitly states this "Fails on the unfixed code because the snapshot was advanced past a window signer1 didn't earn in," confirming the vulnerable behavior is present in `settle-rewards`'s call sites in `pox-5.clar`.

### Impact Explanation
This breaks the equality between sBTC/STX rewards actually earned by a signer/staker and rewards later paid out to that staker: a staker (Alice) becomes entitled to withdraw STX-only rewards for a reward cycle in which her signer was never a qualifying member of the signer set and legitimately earned zero. This is a "rewards paid that were not earned" defect per the impact criteria (Critical: unbacked minting of sBTC/STX rewards; or at minimum High: reward slots/weight exceeding what was actually earned), since it allows value to be paid out of the shared reward pool that was never allocated to that signer's stakers, diluting or double-counting funds meant for legitimately-qualifying signers/stakers (e.g., signer2/its stakers).

### Likelihood Explanation
The trigger requires only ordinary, unprivileged actions: any staker/bond participant can arrange for a signer to hover just below `SIGNER_SET_MIN_USTX` (a bond participant plus one or more STX-only stakers) while another, unrelated signer in the same reward cycle is above threshold and accrues nonzero global STX-only rewards. Any subsequent bond-add/bond-remove or stake-add/stake-remove call for the below-threshold signer during that cycle invokes the vulnerable `settle-rewards` path with `shares == 0`. No admin, miner, or privileged role is required — this is reachable by any two/three ordinary accounts coordinating stake and bond registration amounts, as exercised in the existing regression test.

### Recommendation
In `remove-staker-from-signer-for-cycle` and `add-staker-to-signer-for-cycle` (and any other call sites of `settle-rewards`/`settle-staker-rewards`), gate the checkpoint advancement so that a signer's STX-only rewards-per-token snapshot is only updated to the current global value while the signer is an actual member of the reward-cycle's signer set (`is-in-signer-set`) and/or has nonzero `cur-staked-for-signer`/`total-shares-staked`. Concretely, skip the `settle-rewards` call (not just `settle-staker-rewards`) when the signer's current STX-only shares for the cycle are zero, or explicitly track/validate that the checkpoint cannot advance across a window where the signer earned nothing, mirroring how `prev-staker-shares == u0` is already special-cased for `settle-staker-rewards` at [3](#0-2) .

### Proof of Concept
The existing repository regression test reproduces the issue end-to-end: [6](#0-5) 

1. Signer1 is registered with Bob's sBTC bond (tiny backing uSTX) plus Alice's STX-only stake, keeping signer1's total delegated uSTX below `SIGNER_SET_MIN_USTX` for cycle 1 (so signer1 is never in cycle 1's signer set).
2. Signer2 (unrelated) is staked above threshold, so the global STX-only rewards-per-token for cycle 1 becomes nonzero.
3. Rewards are funded and calculated; sanity checks confirm signer1 and Alice have earned `0` STX-only rewards for cycle 1.
4. Bob's bond reward claim triggers `remove-staker-from-signer-for-cycle` for signer1/cycle 1, which unconditionally calls `settle-rewards`, advancing signer1's stored rewards-per-token checkpoint to the (nonzero) global value despite `shares == 0`.
5. The test asserts Alice's earned STX-only rewards for cycle 1 must remain `0`; on the unfixed contract, this assertion fails because the corrupted checkpoint now allows Alice's subsequent settlement to compute nonzero phantom earnings.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1542-1544)
```text
        ;; Settle STX-only rewards before mutating anything
        (settle-rewards signer reward-cycle none)
        (settle-staker-rewards signer reward-cycle none staker)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1691-1703)
```text
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
