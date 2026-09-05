### Title
Below-threshold signer's zero-share `settle-rewards` corrupts `signer-rewards-per-token-for-cycle`, letting a co-member double count / claim rewards for a cycle it never earned in - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
The reachable analog of the Nouns "quorum ignores burned tokens" bug is in `pox-5.clar`'s per-cycle, per-signer reward-per-token accounting. Just as the Nouns governor used `token.totalSupply()` — a value that includes burned/non-voting tokens — as the denominator for quorum, `pox-5`'s `settle-rewards` path advances a signer's `signer-rewards-per-token-for-cycle` snapshot even when that signer's `shares` for the cycle are `0` (i.e., the signer never qualified for the cycle's stacking threshold, analogous to "burned" stake with no real weight). This lets another staker delegated to the same signer manager collect STX-only rewards for a cycle their signer did not participate in, which is a form of double-counting/unearned reward payout enabled by using a denominator/snapshot that does not reflect the signer's real (non-zero) participation. [1](#0-0) 

### Finding Description
The Nouns bug's root cause is: the quorum denominator (`token.totalSupply()`) includes value (burned tokens) that carries no actual voting weight, so the "real" and "assumed" weight diverge and the equality `realVotingPower == assumedVotingPower - unusable` is broken without the protocol reconciling it.

In `pox-5.clar`, per-cycle signer participation is likewise supposed to satisfy an equality: rewards distributed to a staker for cycle `N` via a signer should be non-zero only if that signer actually held `shares > 0` (i.e., was a qualifying, weight-bearing member) for cycle `N`. The regression test `below-threshold signer leaks phantom stx-only rewards via bond co-claim` in `contrib/core-contract-tests/tests/pox-5/pox-5.test.ts` demonstrates that this invariant is violated:

- `signer1` has a staker (`bob`) whose bond-backed uSTX is far below `SIGNER_SET_MIN_USTX`, and `alice`'s STX-only stake added to it is still confirmed to be below `SIGNER_SET_MIN_USTX`: [2](#0-1) 
- The test explicitly asserts `signer1` is *not* a member of the reward set for cycle 1, and that its `getSignerSharesStakedForCycle` is `0`: [3](#0-2) 
- Despite this, calling `testSigner.claimRewards([0n], 1n)` — which triggers the bond claim and runs `settle-rewards` on `signer1`'s STX-only cycle-1 bucket with `shares == 0` — corrupts the global `signer-rewards-per-token-for-cycle` snapshot, advancing it past a window `signer1` never participated in: [4](#0-3) 
- The test's final (currently-failing-on-unfixed-code) assertion states that `alice` — a staker on `signer1` — must not be owed STX-only rewards for cycle 1, a cycle in which her signer held no qualifying shares: [5](#0-4) 

This is precisely analogous to the Nouns disequation: `realVotingPower < quorum-implied-by-assumedVotingPower`. Here, `real earned shares for signer1/cycle1 == 0` but the reward-per-token accounting still lets a staker on that signer accrue and later claim non-zero rewards for that cycle — i.e., `rewards_paid_to_alice_for_cycle_1 > 0` even though `signer1_shares_for_cycle_1 == 0`, breaking the equality that rewards paid must be backed by actual qualifying stake/participation in that cycle.

### Impact Explanation
This breaks the equality "sBTC/STX rewards paid == rewards actually earned by a signer's qualifying participation," which the rules classify as a Critical-tier issue ("theft or unbacked minting of ... sBTC rewards ... double-counting a commitment or reward"). A staker can be credited STX-only rewards for a cycle where their signer was never a qualifying member of the reward set (weight/shares = 0), meaning rewards are unbacked by any real locked/qualifying commitment for that cycle — directly mirroring the Nouns impact where quorum arithmetic counted value that carried no real voting power.

### Likelihood Explanation
The PoC in the repository's own test suite (`pox-5.test.ts`) demonstrates the exact call sequence required: set up a bond with a staker whose backing uSTX is under `SIGNER_SET_MIN_USTX`, add a second STX-only staker to the same signer keeping it below threshold, have an independent signer advance the global rewards-per-token rate, fund/calculate rewards, and then call `claimRewards` on the bond. This requires no privileged role — only ordinary `stake`, `registerForBond`, and `claimRewards` calls from unprivileged accounts (`alice`, `bob`, `charlie`, `deployer` acting as the funder) — making it a directly reachable and repeatable bug class in `pox-5.clar`'s reward settlement logic.

### Recommendation
In `settle-rewards` (pox-5.clar), guard the advancement/snapshot of `signer-rewards-per-token-for-cycle` (and any per-signer STX-only reward accrual) so that it is only updated/attributed when the signer's `shares` for that specific cycle are non-zero (i.e., the signer actually qualified/was a member of the reward set for that cycle). Where a signer has zero shares for a cycle, either skip advancing that signer's snapshot for the cycle entirely, or explicitly zero out any staker-level accrual derived from that snapshot for cycles in which the signer held no qualifying shares — analogous to recomputing `quorum`/`proposalThreshold` against real (non-burned) voting power in the referenced Nouns fix.

### Proof of Concept
The existing repository test is a self-contained PoC (already committed, intended to fail against the current/unfixed behavior): [1](#0-0) 

Key sequence:
1. `signer1` registers a bond where the only backing staker (`bob`) is far under `SIGNER_SET_MIN_USTX`.
2. `alice` stakes STX-only to `signer1`, keeping the combined total still below `SIGNER_SET_MIN_USTX` — confirmed via `isSignerInCycle({ signer: signer1, cycle: 1n })` returning `false` and `getSignerSharesStakedForCycle(signer1, 1n, null)` returning `0`.
3. `signer2` (a different, above-threshold signer) advances the global STX-only rewards-per-token rate via an independent qualifying stake.
4. Rewards are funded and `calculateRewards` is run.
5. `claimRewards` is invoked on the bond, running `settle-rewards` on `signer1`'s zero-share STX-only bucket for cycle 1.
6. Despite `signer1` having earned nothing (`getEarned(signer1, 1n, null) == 0`), `alice`'s `getEarnedStakerRewards(alice, 1n, null)` becomes non-zero on unfixed code — rewards attributed to a cycle the signer never qualified for.

### Citations

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
