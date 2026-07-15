### Title
Unclaimed Self-Pooling Rewards Permanently Lost When User Bypasses `PoolJoin` Guard via Direct Route Navigation — (File: `packages/gui/src/components/plotNFT/PlotNFTChangePool.tsx`)

### Summary
The `PoolJoin` component enforces a UI-level guard that blocks a self-pooling user from joining a pool while they have unclaimed rewards. However, the actual pool-change submission form (`PlotNFTChangePool`) — reachable directly via its React Router route — contains no equivalent guard. A user who navigates directly to the change-pool route and submits the form will call `pwJoinPool` or `pwSelfPool` without first calling `pwAbsorbRewards`, causing their accumulated self-pooling XCH rewards to be permanently lost.

### Finding Description
`PoolJoin.tsx` is the component that renders the "Join Pool" / "Change Pool" button on the PlotNFT card. It contains an explicit guard:

```ts
if (isSelfPooling && balance) {
  await openDialog(<AlertDialog>You need to claim your rewards first</AlertDialog>);
  return;
}
navigate(`/dashboard/pool/${p2SingletonPuzzleHash}/change-pool`);
``` [1](#0-0) 

This guard only exists in the button component. The route it navigates to — `PlotNFTChangePool` — is independently reachable. Its `handleSubmit` function performs no check for unclaimed rewards before calling `pwSelfPool` or `pwJoinPool`:

```ts
async function handleSubmit(dataLocal: SubmitData) {
  const walletId = nft?.poolWalletStatus.walletId;
  // ...
  if (walletId === undefined || poolUrl === nft?.poolState.poolConfig.poolUrl) {
    return;
  }
  if (stateLocal === 'SELF_POOLING') {
    await pwSelfPool({ walletId, fee }).unwrap();
  } else {
    await pwJoinPool({ walletId, poolUrl, relativeLockHeight, targetPuzzlehash: targetPuzzleHash, fee }).unwrap();
  }
  navigate(-1);
}
``` [2](#0-1) 

The `confirmedWalletBalance` of the pool wallet — displayed in the UI as "Unclaimed Rewards" — is the on-chain balance that `pwAbsorbRewards` (`pw_absorb_rewards`) moves to the standard wallet. The existence of the guard in `PoolJoin.tsx` and the explicit "You need to claim your rewards first" message confirm that calling `pwJoinPool`/`pwSelfPool` without first absorbing rewards causes those rewards to be unrecoverable at the protocol level. [3](#0-2) 

The `usePlotNFTDetails` hook exposes `balance` (mapped from `confirmedWalletBalance`) and `isSelfPooling`, both of which are available in `PlotNFTChangePool` via the `nft` object already fetched from `useGetPlotNFTsQuery`, but neither is checked before submission. [4](#0-3) 

### Impact Explanation
A user in `SELF_POOLING` state with a non-zero `confirmedWalletBalance` who navigates directly to `/dashboard/pool/<p2SingletonPuzzleHash>/change-pool` (bypassing the `PoolJoin` button guard) and submits the form will trigger `pwJoinPool` or `pwSelfPool` without first absorbing rewards. The accumulated XCH pooled farming rewards are permanently lost — an irreversible balance/accounting change affecting XCH and pooled farming rewards. This matches the Critical impact tier.

### Likelihood Explanation
Medium. The Electron app's React Router routes are navigable directly (e.g., by pasting the URL or via browser history). The guard exists only in the button component, not in the destination route. A user who is aware of the URL structure, or who arrives at the route through any path other than the guarded button (e.g., browser back/forward, deep link, or scripted navigation), can trigger the loss. The pattern is directly analogous to the external report: the front-end enforces the correct sequence only at one entry point, leaving the underlying action unguarded.

### Recommendation
Add the same unclaimed-rewards check inside `PlotNFTChangePool.handleSubmit` before dispatching `pwSelfPool` or `pwJoinPool`. Specifically, read `isSelfPooling` and `balance` from `usePlotNFTDetails(nft)` (or directly from `nft.walletBalance.confirmedWalletBalance` and the current state) and abort with a clear error if `isSelfPooling && balance > 0`. This mirrors the guard already present in `PoolJoin.tsx` and closes the bypass path. [5](#0-4) 

### Proof of Concept
1. Create a PlotNFT and set it to self-pooling (`SELF_POOLING` state).
2. Farm until `confirmedWalletBalance > 0` (unclaimed rewards accumulate).
3. Do **not** click "Claim Rewards." Instead, directly navigate in the Electron app to `/dashboard/pool/<p2SingletonPuzzleHash>/change-pool`.
4. Select a pool URL and submit the form.
5. `pwJoinPool` is called without a prior `pwAbsorbRewards` call.
6. The accumulated XCH rewards are permanently lost; the `PoolJoin.tsx` guard was never reached. [6](#0-5) [7](#0-6)

### Citations

**File:** packages/gui/src/components/pool/PoolJoin.tsx (L31-38)
```typescript
    if (isSelfPooling && balance) {
      await openDialog(
        <AlertDialog>
          <Trans>You need to claim your rewards first</Trans>
        </AlertDialog>,
      );
      return;
    }
```

**File:** packages/gui/src/components/plotNFT/PlotNFTChangePool.tsx (L36-63)
```typescript
  async function handleSubmit(dataLocal: SubmitData) {
    const walletId = nft?.poolWalletStatus.walletId;

    const {
      initialTargetState: { state: stateLocal, poolUrl, relativeLockHeight, targetPuzzleHash },
      fee,
    } = dataLocal;

    if (walletId === undefined || poolUrl === nft?.poolState.poolConfig.poolUrl) {
      return;
    }

    if (stateLocal === 'SELF_POOLING') {
      await pwSelfPool({
        walletId,
        fee,
      }).unwrap();
    } else {
      await pwJoinPool({
        walletId,
        poolUrl,
        relativeLockHeight,
        targetPuzzlehash: targetPuzzleHash, // pw_join_pool expects 'target_puzzlehash', not 'target_puzzle_hash'
        fee,
      }).unwrap();
    }

    navigate(-1);
```

**File:** packages/gui/src/components/plotNFT/PlotNFTCard.tsx (L133-137)
```typescript
    isSelfPooling && {
      key: 'rewards',
      label: <Trans>Unclaimed Rewards</Trans>,
      value: <UnitFormat value={mojoToChiaLocaleString(balance)} state={State.SUCCESS} />,
    },
```

**File:** packages/gui/src/hooks/usePlotNFTDetails.ts (L31-44)
```typescript
      walletBalance: { confirmedWalletBalance },
    } = nft;

    const isPending = !!target && target.state !== state;
    const isLeavingPool = state === PlotNFTState.LEAVING_POOL;
    const isSelfPooling = state === PlotNFTState.SELF_POOLING;

    return {
      isPending,
      state,
      walletId,
      isSynced: isWalletSynced,
      balance: confirmedWalletBalance,
      canEdit: isWalletSynced && (!isPending || isLeavingPool),
```

**File:** packages/gui/src/components/pool/PoolAbsorbRewards.tsx (L22-28)
```typescript
  async function handleAbsorbRewards() {
    if (!canEdit) {
      return;
    }

    navigate(`/dashboard/pool/${p2SingletonPuzzleHash}/absorb-rewards`);
  }
```
