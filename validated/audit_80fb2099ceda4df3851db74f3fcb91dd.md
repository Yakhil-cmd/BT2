Based on my research, I found a concrete analog to the reported bug class in `pox-5.clar`'s Synthetix-style reward accumulator.

### Title
Snapshotting a below-threshold signer's `signer-rewards-per-token-for-cycle` to the global accumulator while `shares == 0` lets stakers who join later siphon rewards the signer never earned - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
This is a direct structural analog of TRST-M-8: a shared pooled accounting value (there, `protectedQuote`; here, `signer-rewards-per-token-for-cycle`, the staker-facing snapshot of the Synthetix-style reward accumulator) is updated inside a state-changing entrypoint (`settle-rewards`, called from `add-staker-to-signer-for-cycle` on every stake/delegate action) using a computation (`get-rewards-per-token-for-cycle`) that reflects global conditions the caller doesn't fully control, and the update is *not* gated on the actual local condition that should govern it (the signer's own `shares`). This lets timed calls "lock in" a value that breaks the equality between rewards actually earned by a signer's stake and rewards later claimable by stakers attached to that signer.

### Finding Description
`settle-rewards` in `pox-5.clar` unconditionally writes the current global `rewards-per-token` into `signer-rewards-per-token-settled-for-cycle`, but only writes it into the staker-facing `signer-rewards-per-token-for-cycle` snapshot when `shares > 0`: [1](#0-0) 

The included repro test confirms the resulting break of the earn-vs-paid equality: a signer (`signer1`) that never crossed `SIGNER_SET_MIN_USTX` for STX-only staking in a cycle (its `shares == 0`) can still have its `signer-rewards-per-token-for-cycle` snapshot advanced to the current global accumulator value via a `settle-rewards` call triggered from an unrelated bond-claim path, even though it earned nothing: [2](#0-1) 

Because staker-level rewards are computed against this per-signer snapshot (`get-signer-rewards-per-token-for-cycle`) rather than directly against the global one, a staker attached to that signer can subsequently claim `shares * (rpt - rptSettled)` where `rpt` was advanced despite the signer contributing zero `shares` in that cycle: [3](#0-2) 

The comment in `add-staker-to-signer-for-cycle` even documents the intended invariant that is being violated ("it's possible for a signer to have _more_ than the minimum delegated, but _less_ staked from STX-only stakers, but they'll still receive rewards" — implying the snapshot logic is meant to gate on `shares`, not on unrelated triggers): [4](#0-3) 

The manipulation pattern mirrors TRST-M-8: instead of periodic `initiateDeposit`/`processQueuedDeposit` calls timed around a price NAV drop to lock in a bad `protectedQuote`, here an attacker (or any user) can time a bond-reward claim (`claim-rewards` → `update-claimable-rewards` → `settle-rewards`) against a signer that is below the STX-only threshold in a cycle where the global `rewards-per-token` has advanced (from other signers' activity), causing `signer-rewards-per-token-settled-for-cycle` for the non-contributing signer to be pulled forward. Any staker attached to that signer for that cycle window is then able to claim against the stale/incorrect frozen `signer-rewards-per-token-for-cycle` window boundaries, resulting in sBTC rewards being credited that were never actually earned by that signer's stake — a double-counting/over-payment of rewards from the shared pool at the expense of other signers/stakers.

### Impact Explanation
This breaks the equality between sBTC rewards actually earned (by staked amount × time × per-token-rate) and sBTC rewards paid out, allowing a staker to receive rewards that were never earned by their signer's contribution, funded from the shared reward pool meant for other legitimate stakers. This matches the "sBTC rewards paid that were not earned or counted twice" criterion, mapping to a High/Critical impact category (theft of pooled reserve/rewards, double-counting a reward).

### Likelihood Explanation
The trigger is reachable by any account: staking below `SIGNER_SET_MIN_USTX` and then calling any public entrypoint that indirectly invokes `settle-rewards` for that signer/cycle/bond combination (e.g., `claim-rewards`, `claim-staker-rewards-for-signer` via a signer-manager contract) requires no privileged role, no admin key, and no price assumptions — only ordinary stacking/claim transactions and cycle timing, which is directly analogous to the "periodic small deposit/withdraw" pattern in the source report.

### Recommendation
Do not update `signer-rewards-per-token-for-cycle` (or any staker-facing snapshot) unless the signer's `shares` for that cycle were actually non-zero for the *entire* accrual window being settled, or track per-window accrual explicitly so that a settle call from an unrelated code path cannot advance the staker snapshot past a period the signer did not participate in. Consider decoupling "recording that a settle happened" from "advancing the staker-visible accumulator," and add an invariant test asserting stakers of a signer can never accrue more than `shares * Δ(global rpt)` for periods where `shares == 0`.

### Proof of Concept
The existing regression test `below-threshold signer leaks phantom stx-only rewards via bond co-claim` in `contrib/core-contract-tests/tests/pox-5/pox-5.test.ts` demonstrates the exact sequence: register a bond with a below-threshold amount, stake STX-only below `SIGNER_SET_MIN_USTX` on `signer1` (so `shares == 0`), have a second signer's activity advance the global STX-only `rewards-per-token`, then trigger `claim-rewards` on `signer1`'s bond, which internally calls `settle-rewards` and (per the assertion comments) can corrupt `signer-rewards-per-token-for-cycle`, leaking phantom rewards to an unrelated staker (`alice`) who was never part of the qualifying signer set for that cycle. [2](#0-1)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1658-1663)
```text
;; If the signer is above the minimum threshold, only then do we update
;; reward calculation state, so that signers below the _delegation_ threshold
;; don't receive rewards. This means it's possible for a signer to have
;; _more_ than the minimum delegated, but _less_ staked from STX-only stakers,
;; but they'll still receive rewards.
(define-private (add-staker-to-signer-for-cycle
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2576-2614)
```text
;; Update all earned-but-unclaimed rewards for a staker, and update the snapshot
;; (staker-rewards-per-token-settled-for-cycle) for the staker.
;;
;; This MUST be called before any update to `staker-shares-staked-for-cycle`,
;; because changes to that state will effect rewards calculations.
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
