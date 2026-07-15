The code confirms the race condition is real. Let me trace the two independent fetch paths precisely.

**Display path** (`PlotNFTSelectBase.tsx` line 39): `usePoolInfo(poolUrl)` → `getPoolInfo(normalizedUrl)` → `window.appAPI.fetchPoolInfo(poolUrl)` — result shown to user in `<PoolInfo poolInfo={poolInfo.poolInfo} />`.

**Submit path** (`PlotNFTSelectPool.tsx` line 123): `handleSubmit` → `prepareSubmitData(data)` → `getPoolInfo(normalizedPoolUrl)` (line 29) → `window.appAPI.fetchPoolInfo(poolUrl)` — result's `targetPuzzleHash` passed directly to `pwJoinPool`.

These are two completely independent HTTP fetches to the pool server with no cross-check between them.

---

### Title
TOCTOU Race: Malicious Pool Server Can Substitute `targetPuzzleHash` Between Display and Submit, Redirecting Farming Rewards — (`packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx`)

### Summary
`PlotNFTSelectPool` fetches pool info twice from the external pool server: once for display (via `usePoolInfo` in `PlotNFTSelectBase`) and once at submit time (via `prepareSubmitData`). A malicious pool operator can return a legitimate `targetPuzzleHash` on the first request (shown to the user for review) and a different, attacker-controlled `targetPuzzleHash` on the second request (submitted to `pwJoinPool`). The user approves one destination; the blockchain transaction encodes a different one.

### Finding Description
In `PlotNFTSelectBase.tsx`, the pool info displayed to the user is fetched by `usePoolInfo(poolUrl)`: [1](#0-0) 

This result is rendered in the "Verify Pool Details" card: [2](#0-1) 

When the user clicks submit, `handleSubmit` calls `prepareSubmitData`, which makes a **second, independent** HTTP fetch to the same pool URL: [3](#0-2) 

The `targetPuzzleHash` returned by this second fetch is what gets embedded in the `pwJoinPool` RPC call: [4](#0-3) 

Which ultimately reaches `pwJoinPool` in `PlotNFTChangePool.tsx`: [5](#0-4) 

There is no code anywhere that compares the `targetPuzzleHash` shown to the user against the one submitted. The two fetches are entirely decoupled.

### Impact Explanation
`targetPuzzleHash` in `pw_join_pool` is the puzzle hash to which the singleton pays farming rewards when a block is found. If an attacker substitutes their own puzzle hash at submit time, all future farming rewards from that Plot NFT are paid to the attacker's address. The user has no indication anything went wrong — the UI showed the legitimate pool's hash, and the transaction confirmation does not re-display the submitted hash for comparison. This is a direct, irreversible payout redirection affecting pooled farming rewards, fitting the Critical scope.

### Likelihood Explanation
Any operator of a pool server the user connects to can trivially implement this: serve the legitimate `targetPuzzleHash` on the first `/pool_info` request and an attacker-controlled hash on the second. The window between the two fetches is the user's review time (seconds to minutes), which is ample. No special access, leaked keys, or local compromise is required — only control of the pool HTTP endpoint, which is the attacker's own server.

### Recommendation
Capture the pool info result from the display fetch and pass it through to `prepareSubmitData` rather than re-fetching. Concretely:

1. Store the `poolInfo` object returned by `usePoolInfo` in component state when it resolves.
2. Pass that cached object into `prepareSubmitData` (or directly into `handleSubmit`) instead of calling `getPoolInfo` again.
3. If a re-fetch is ever needed (e.g., for freshness), display the new values to the user and require explicit re-confirmation before proceeding.

### Proof of Concept
Mock `getPoolInfo` (or `window.appAPI.fetchPoolInfo`) to return `targetPuzzleHash = "0xLEGIT..."` on the first call and `targetPuzzleHash = "0xATTACKER..."` on the second call. Render `PlotNFTSelectPool`, enter a pool URL, wait for the display to show `0xLEGIT...`, then click submit. Assert that the argument passed to `pwJoinPool` contains `targetPuzzlehash: "0xATTACKER..."` — confirming the submitted hash differs from the reviewed hash. [6](#0-5)

### Citations

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx (L39-39)
```typescript
  const poolInfo = usePoolInfo(poolUrl);
```

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx (L132-139)
```typescript
      <StyledCollapse in={showPoolInfo}>
        <CardStep step={typeof step === 'number' ? step + 1 : undefined} title={<Trans>Verify Pool Details</Trans>}>
          {poolInfo.error && <Alert severity="warning">{poolInfo.error.message}</Alert>}

          {poolInfo.loading && <Loading center />}

          {poolInfo.poolInfo && <PoolInfo poolInfo={poolInfo.poolInfo} />}
        </CardStep>
```

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx (L21-48)
```typescript
async function prepareSubmitData(data: FormData): SubmitData {
  const { self, fee, poolUrl } = data;
  const initialTargetState = {
    state: self ? 'SELF_POOLING' : 'FARMING_TO_POOL',
  };

  if (!self && poolUrl) {
    const normalizedPoolUrl = normalizeUrl(poolUrl);
    const { targetPuzzleHash, relativeLockHeight } = await getPoolInfo(normalizedPoolUrl);
    if (!targetPuzzleHash) {
      throw new Error(t`Pool does not provide targetPuzzleHash.`);
    }
    if (relativeLockHeight === undefined) {
      throw new Error(t`Pool does not provide relativeLockHeight.`);
    }

    initialTargetState.poolUrl = normalizedPoolUrl;
    initialTargetState.targetPuzzleHash = targetPuzzleHash;
    initialTargetState.relativeLockHeight = relativeLockHeight;
  }

  const feeMojos = chiaToMojo(fee || '0');

  return {
    fee: feeMojos,
    initialTargetState,
  };
}
```

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx (L123-125)
```typescript
        const submitData = await prepareSubmitData(data);

        await onSubmit(submitData);
```

**File:** packages/gui/src/components/plotNFT/PlotNFTChangePool.tsx (L54-60)
```typescript
      await pwJoinPool({
        walletId,
        poolUrl,
        relativeLockHeight,
        targetPuzzlehash: targetPuzzleHash, // pw_join_pool expects 'target_puzzlehash', not 'target_puzzle_hash'
        fee,
      }).unwrap();
```

**File:** packages/gui/src/util/getPoolInfo.ts (L1-7)
```typescript
import type { PoolInfo } from '@chia-network/api';
import { toCamelCase } from '@chia-network/api';

export default async function getPoolInfo(poolUrl: string): Promise<PoolInfo> {
  const data = await window.appAPI.fetchPoolInfo(poolUrl);
  return toCamelCase(data) as PoolInfo;
}
```
