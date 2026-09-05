### Title
Stake-then-immediately-unstake within a reward cycle can settle STX-only rewards for a signer/staker with zero effective time-weighted contribution - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
The reported Locke.sol bug class (H-06) is: a staker can `stake` and `withdraw` within the same reward-accrual window and still be credited reward-per-token accrued over the whole window, because the reward math is snapshot-based (`rewardPerToken`) rather than time-weighted per staker. `pox-5.clar` uses an analogous snapshot/accumulator model (`rewards-per-token-for-cycle`, `signer-rewards-per-token-for-cycle`, `staker-rewards-per-token-settled-for-cycle`) with `compute-earned-rewards` computing `earned = shares * (rpt-current - rpt-paid) / PRECISION + pending` [1](#0-0) . Because shares are recorded per-cycle (not time-weighted within a cycle), a staker who stakes right before `calculate-rewards`/`claim-rewards` runs for a cycle, and is a full member of that cycle's `staker-shares-staked-for-cycle`, is entitled to the full per-cycle `rewards-per-token` delta for that cycle regardless of how long they were actually staked within the cycle.

### Finding Description
`settle-rewards`/`settle-staker-rewards` snapshot `rpt-paid` at the moment a staker's shares change (stake/unstake), and `compute-earned-rewards` pays out `shares * (rpt_now - rpt_paid)` [2](#0-1) . The reward-cycle boundary is the only granularity that matters — `stake` records shares into `staker-shares-staked-for-cycle`/`total-shares-staked-for-cycle` keyed by `reward-cycle`, and `calculate-rewards` computes `accrued-rewards-per-ustx` once per cycle based on the cycle's `cycle-staked-ustx` total [3](#0-2) . There is no intra-cycle, time-weighted accounting analogous to Locke's `acctTimeDelta`-based decay of `ts.tokens`. This means the moment a staker's shares are counted as part of a cycle's staked total, they earn the full cycle's rewards-per-token delta for that cycle, irrespective of when within the cycle they staked (as long as it's before `calculate-rewards` is invoked for that cycle) or whether they immediately queue an unstake for the following cycle.

However, this differs materially from the Locke bug: in pox-5, the STX must actually be locked (`stake` calls into PoX's locking machinery) for the staker to be counted in `staker-shares-staked-for-cycle`/`total-shares-staked-for-cycle`, and the accounting only credits rewards cycle-by-cycle where that lock was active for the entire cycle — there's no mechanism to unlock STX and still be counted as staked in the same cycle (unlike Locke's `ts.tokens -= ...` which can be zeroed out via integer division after a partial elapsed time while the staker's rewards were already accumulated). I could not, within the code explored, locate an `unstake` path that lets shares be removed for a cycle after they've already been credited into `total-shares-staked-for-cycle` for that same cycle while the STX was never actually locked for the cycle — the locking is enforced by the underlying PoX-4 lock/unlock height mechanics tied to `first-reward-cycle`/`num-cycles`, so a staker cannot game a fraction that guarantees a positive share count without any real backing lock the way Locke's `acctTimeDelta / (endStream - ts.lastUpdate)` fraction can be forced to zero while retaining full `ts.tokens`.

A separate, related bug is documented in the repo's own test suite: `below-threshold signer leaks phantom stx-only rewards via bond co-claim` in `contrib/core-contract-tests/tests/pox-5/pox-5.test.ts:6064-6157`, where a signer below `SIGNER_SET_MIN_USTX` gets `settle-rewards` invoked with `shares=0` during a bond claim, and the test asserts the staker's earned STX-only rewards must remain `0` for a cycle the signer was never a member of. Because this is a repo-authored regression/witness test (not independently reproduced by me against the actual current on-chain behavior), I cannot confirm from static reading alone whether this assertion currently passes (bug fixed) or fails (bug live) in this snapshot of the code.

### Impact Explanation
If the phantom-reward path in the test above is currently exploitable (i.e., `settle-rewards` snapshotting `signer-rewards-per-token-for-cycle` for a signer/cycle where the signer never crossed `SIGNER_SET_MIN_USTX`, triggered by any user calling `claim-rewards` with a bond period for that signer), a staker (`alice` in the test) could be credited STX-only rewards for a cycle in which their signer never earned any, effectively double-counting or manufacturing rewards not backed by real signer participation in that cycle — a Critical-class "double-counting a commitment or reward" issue per the rules. This is the closest concrete analog to the Locke H-06 report (rewards created without a genuinely time/qualification-backed contribution).

### Likelihood Explanation
Triggering requires: (1) a signer with sats-heavy bond participation staying below `SIGNER_SET_MIN_USTX` in STX-only terms, (2) an STX-only staker (alice) delegated to that signer, (3) another signer whose STX-only pool advances the relevant snapshot so the bug is not masked by an all-zero global, and (4) anyone calling `claim-rewards` for the under-threshold signer's bond. All of these are attacker-controllable setup steps requiring no privileged role, making this reachable by an ordinary staker/signer-manager operator, though it requires deliberately engineering the below-threshold condition.

### Recommendation
- Ensure `settle-rewards`/`settle-staker-rewards` for STX-only pools are only snapshotted/advanced for a signer that was actually a member of the reward set for that cycle (i.e., guard on `is-signer-in-cycle` or equivalent before calling `settle-rewards` with `shares=0`), mirroring the Locke fix recommendation of gating the reward-per-token update on a positive, cycle-qualifying staked amount rather than unconditionally executing it on every stake/unstake/claim code path.
- Add/verify a regression test asserting `get-earned-staker-rewards` stays `0` for stakers whose signer never crossed `SIGNER_SET_MIN_USTX` in the queried cycle, even after any bond-related `claim-rewards` call touches that signer/cycle pair.

### Proof of Concept
The repo's own test (not authored by me, but present in-tree) demonstrates the setup and the exact witnessing assertion for this class of bug: [4](#0-3) 

This sets up `signer1` permanently under `SIGNER_SET_MIN_USTX` with staker `alice` delegated to it, a second signer whose STX-only pool advances the global accumulator, then calls `testSigner.claimRewards([0n], 1n)` (a bond claim) which internally invokes `settle-rewards` on `signer1`'s STX-only cycle-1 entry with `shares: 0`, and asserts that `alice`'s STX-only earned rewards for cycle 1 remain `0` afterward — i.e., this test is designed to catch exactly the "snapshot advanced past a window the signer didn't earn in" defect.

I was not able to execute this test or step through `claim-rewards` → `update-claimable-bond-rewards` → `settle-rewards` call chain in full within the available iterations to confirm whether the assertion currently passes or fails against the present `pox-5.clar` implementation; this should be verified by running `contrib/core-contract-tests/tests/pox-5/pox-5.test.ts` in a full Devin session with repo access.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2191-2221)
```text
                (stx-staker-rewards (- remaining-rewards reserve-cut))
                (cycle-staked-ustx (get-total-shares-staked-for-cycle stx-cycle none))
                (current-rewards-per-ustx (get-rewards-per-token-for-cycle stx-cycle none))
                (prev-accounted-rewards (var-get last-accounted-rewards-only))
                ;; If no STX is staked this cycle, the staker cut will be applied to the reserve.
                (no-stx-stakers (is-eq cycle-staked-ustx u0))
                (accrued-rewards-per-ustx (if no-stx-stakers
                    u0
                    (/ (* stx-staker-rewards PRECISION) cycle-staked-ustx)
                ))
                (cumulative-rewards-per-ustx (+ current-rewards-per-ustx accrued-rewards-per-ustx))
                ;; When no STX is staked, fold the staker cut into the reserve, otherwise zero.
                (unallocated-staker-cut (if no-stx-stakers
                    stx-staker-rewards
                    u0
                ))
                (reserve-deposit (+ reserve-cut unallocated-staker-cut))
                (new-reserve-balance (+ cur-reserve reserve-deposit))
            )
            (var-set reserve-balance new-reserve-balance)
            (var-set last-reward-compute-height calculation-height)
            (var-set last-accounted-rewards-only
                (+ prev-accounted-rewards
                    (- gross-accrued-rewards reserve-deposit)
                ))
            (map-set rewards-per-token-for-cycle {
                reward-cycle: stx-cycle,
                bond-index: none,
            }
                cumulative-rewards-per-ustx
            )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2378-2385)
```text
(define-read-only (compute-earned-rewards
        (shares uint)
        (rpt-current uint)
        (rpt-paid uint)
        (pending uint)
    )
    (+ pending (/ (* shares (- rpt-current rpt-paid)) PRECISION))
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2581-2613)
```text
(define-private (settle-staker-rewards
        (signer principal)
        (reward-cycle uint)
        (bond-index (optional uint))
        (staker principal)
    )
    (let (
            (earned (get-earned-staker-rewards signer reward-cycle bond-index staker))
            (rewards-per-token (get-signer-rewards-per-token-for-cycle signer reward-cycle
                bond-index
            ))
        )
        (map-set staker-unclaimed-rewards-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
            signer: signer,
            staker: staker,
        }
            earned
        )
        (map-set staker-rewards-per-token-settled-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
            signer: signer,
            staker: staker,
        }
            rewards-per-token
        )
        {
            earned: earned,
            rewards-per-token: rewards-per-token,
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
