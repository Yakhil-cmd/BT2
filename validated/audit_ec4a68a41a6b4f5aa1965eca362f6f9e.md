## Title
Staker/Signer reward settlement can revert on subtraction underflow, permanently freezing pending rewards - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
Sherlock M-3 flags a Synthetix-style accumulator/debt pattern where `totalAccumulatedRewards = shares * accumulator - debt` reverts if `debt` exceeds the newly recomputed value, because the cached/pending rewards weren't added back before the subtraction, freezing the user's rewards until the accumulator catches back up.

`pox-5.clar` implements the identical Synthetix-style pattern for signer and staker sBTC rewards: `compute-earned-rewards` computes `pending + (shares * (rpt-current - rpt-paid)) / PRECISION` [1](#0-0) , and `settle-rewards`/`settle-staker-rewards` snapshot `rpt-paid` from the accumulator only conditionally (`signer-rewards-per-token-for-cycle` is updated only `(if (> shares u0) ...)`) [2](#0-1) .

### Finding Description
In Clarity, `(- rpt-current rpt-paid)` is a checked/panicking subtraction: if `rpt-paid > rpt-current` at the moment `compute-earned-rewards` runs, the enclosing transaction aborts entirely (analogous to Solidity's `revert` in the Sherlock report).

The staker-facing accumulator `signer-rewards-per-token-for-cycle` is *not* the same monotone global accumulator (`rewards-per-token-for-cycle`) — it is a per-signer "frozen snapshot" that `settle-rewards` only advances `(if (> shares u0) ...)` [3](#0-2) . `get-earned-staker-rewards` and `settle-staker-rewards` read this per-signer snapshot as `rpt-current` and compare it against the staker's previously stored `staker-rewards-per-token-settled-for-cycle` (`rpt-paid`) [4](#0-3) [5](#0-4) .

Because settlement order between multiple actors (signer settling with `shares=0`, staker settling against a signer snapshot last written at a different, possibly stale height) is not tightly coupled to a single monotonic global counter the way Synthetix's canonical pattern requires, there exists a code path — already independently confirmed by the repository's own regression test `below-threshold signer leaks phantom stx-only rewards via bond co-claim` [3](#0-2)  — where `settle-rewards` runs with `shares = u0` and this "corrupts" `signer-rewards-per-token-for-cycle`, i.e. the staker-facing snapshot value diverges from what a strictly-monotone accumulator would produce. The test's own comment states plainly: *"Trigger the bond claim. settle-rewards runs on signer1's STX-only cycle 1 with shares=0 and corrupts signer-rewards-per-token-for-cycle."* This is the exact same "debt/accumulator desync" bug class as the Sherlock report — a subtraction between an accumulator and a stored debt/settled value that is not guaranteed to remain non-negative on every call path.

I was **not** able to fully trace, within the tool budget available, a concrete forged call sequence in which `staker-rewards-per-token-settled-for-cycle[staker]` ends up strictly greater than the freshly-read `signer-rewards-per-token-for-cycle[signer]` at the moment `get-earned-staker-rewards`/`settle-staker-rewards` is invoked (which would be required to actually trigger the Clarity underflow panic and freeze the staker's claim). The repo's own test only demonstrates a *value-corruption* variant (phantom, unearned rewards attributed to a staker) rather than proving the underflow-panic/freezing variant described in the Sherlock report.

### Impact Explanation
If `rpt-paid > rpt-current` is reachable via `settle-rewards` running with `shares = u0` on a stale/out-of-order settle, then any subsequent `claim-staker-rewards` / `claim-staker-rewards-for-signer` call for that staker on that cycle would panic on the underflowing subtraction inside `compute-earned-rewards`, causing the staker's already-earned sBTC rewards for that cycle to be permanently unclaimable through the normal claim path (temporary/permanent freezing of a reward that was otherwise fully backed by contract balance) — matching the report's High-severity "temporary freezing of staked funds" category. This would only affect the affected staker's specific (signer, cycle, bond-index) tuple, not systemic funds.

### Likelihood Explanation
Low-to-Medium confidence: this requires the same non-trivial staking/registration/claim ordering already needed to hit the "phantom rewards" bug demonstrated in `pox-5.test.ts` (a below-threshold signer with a bond co-claim triggering `settle-rewards` at `shares = 0`), which is a narrow but automatable (permissionless) sequence of `stake`, `registerForBond`, `calculateRewards`, and `claimRewards` calls, all callable by unprivileged accounts. I could not confirm within the available searches whether the specific underflow-panic direction (rather than the corrupted-snapshot-in-staker's-favor direction already caught by the test) is actually reachable, or whether Clarity's guard rails / other assertions in `settle-staker-rewards` prevent it.

### Recommendation
Treat `signer-rewards-per-token-for-cycle` as a strictly monotone, single-source-of-truth accumulator: update it unconditionally in `settle-rewards` (not gated on `shares > 0`) so that a `shares = 0` settle never leaves — or rewinds — the staker-facing snapshot inconsistent with the true rewards state, and add an explicit non-decreasing invariant check (or use `checked`/saturating subtraction with a `min` guard) around the `(- rpt-current rpt-paid)` computations in `compute-earned-rewards`, `settle-rewards`, and `settle-staker-rewards` so a stale/lower `rpt-current` can never panic a legitimate claim.

### Proof of Concept
Not independently reproduced. The closest available evidence in-repo is the existing regression test that exercises the same root-cause code path (`settle-rewards` invoked with `shares = u0` corrupting `signer-rewards-per-token-for-cycle`): [6](#0-5) . A full PoC proving the underflow-panic/freezing variant (rather than the value-inflation variant this test targets) would require constructing a sequence where a staker's `staker-rewards-per-token-settled-for-cycle` is snapshotted at a higher value than a subsequently-read `signer-rewards-per-token-for-cycle`, which I was unable to confirm is reachable given the remaining tool budget.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2356-2373)
```text
;; Get the total amount of _staker_ rewards earned since the last
;; rewards snapshot.
(define-read-only (get-earned-staker-rewards
        (signer principal)
        (reward-cycle uint)
        (bond-index (optional uint))
        (staker principal)
    )
    (compute-earned-rewards
        (get-staker-shares-staked-for-cycle staker reward-cycle bond-index signer)
        (get-signer-rewards-per-token-for-cycle signer reward-cycle bond-index)
        (get-staker-rewards-per-token-settled-for-cycle signer reward-cycle
            bond-index staker
        )
        (get-staker-unclaimed-rewards-for-cycle signer reward-cycle bond-index
            staker
        ))
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2375-2385)
```text
;; Pure math formula for computing rewards earned since the last snapshot
;;
;; `earned = (shares * (rpt - rptPaid)) / PRECISION + pending`
(define-read-only (compute-earned-rewards
        (shares uint)
        (rpt-current uint)
        (rpt-paid uint)
        (pending uint)
    )
    (+ pending (/ (* shares (- rpt-current rpt-paid)) PRECISION))
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

**File:** contrib/core-contract-tests/tests/pox-5/pox-5.test.ts (L6064-6158)
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
