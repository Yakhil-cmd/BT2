### Title
Malicious Pool Operator Can Serve Different `targetPuzzleHash` Between Display and Submission, Redirecting All Pooled Farming Rewards - (File: `packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx`)

---

### Summary

When a user joins or changes a pool, the Chia GUI makes **two independent HTTP requests** to the pool's `/pool_info` endpoint: one to display pool details to the user, and a second one at submit time to populate the actual on-chain transaction. A malicious pool operator can serve different `targetPuzzleHash` (or `relativeLockHeight`) between these two fetches. The user approves terms based on the first response, but the Plot NFT is created with parameters from the second response — which can redirect all future pooled farming rewards (7/8 of block rewards) to an attacker-controlled address.

---

### Finding Description

The pool-joining flow involves two separate, uncorrelated fetches to the pool's `/pool_info` endpoint:

**Fetch 1 — Display only** (`PlotNFTSelectBase.tsx`, line 39):
```ts
const poolInfo = usePoolInfo(poolUrl);
```
This calls `getPoolInfo` via `usePoolInfo` and renders the result in `<PoolInfo poolInfo={poolInfo.poolInfo} />` for the user to review.

**Fetch 2 — Used in the actual transaction** (`PlotNFTSelectPool.tsx`, lines 29–39):
```ts
const { targetPuzzleHash, relativeLockHeight } = await getPoolInfo(normalizedPoolUrl);
// ...
initialTargetState.targetPuzzleHash = targetPuzzleHash;
initialTargetState.relativeLockHeight = relativeLockHeight;
```
This second fetch happens inside `prepareSubmitData`, which is called at form submission time — after the user has already reviewed and confirmed the terms from Fetch 1.

Both fetches ultimately call `window.appAPI.fetchPoolInfo(poolUrl)`, which hits `${poolUrl}/pool_info` via the Electron main process:

```ts
ipcMainHandle(AppAPI.FETCH_POOL_INFO, async (poolUrl: string) => {
  const poolInfoUrl = `${poolUrl}/pool_info`;
  return fetchJSON(poolInfoUrl);
});
```

There is **no comparison** between the displayed pool info and the submitted pool info. The `targetPuzzleHash` and `relativeLockHeight` values used in `pwJoinPool` / `pwSelfPool` come exclusively from Fetch 2, which the user never sees.

---

### Impact Explanation

The `targetPuzzleHash` is encoded directly into the user's Plot NFT on-chain when they join a pool. It is the puzzle hash to which the 7/8 pool portion of every block reward is sent. If a malicious pool serves a different `targetPuzzleHash` at submit time (e.g., an address they control but never distribute from), **all future pooled farming rewards are permanently redirected** to the attacker for as long as the user remains in that pool. The user has no indication anything went wrong — the join transaction succeeds normally.

This matches the Critical impact criterion: **unauthorized payout change affecting pooled farming rewards**.

Additionally, a changed `relativeLockHeight` (e.g., from 32 blocks to 4608 blocks) would lock the user into the malicious pool far longer than agreed, compounding the reward theft.

---

### Likelihood Explanation

Any party can operate a Chia pool — the pool operator is explicitly an untrusted actor. The attack requires only that the pool's HTTP server return different JSON for the two sequential requests to `/pool_info`. This is trivially implementable (e.g., serve the honest response for the first request per session, then switch on the second). The user has no way to detect the discrepancy because the GUI never cross-checks the two responses.

---

### Recommendation

Cache the pool info response from the display-time fetch and reuse it in `prepareSubmitData` instead of making a second network request. Concretely, pass the already-fetched `poolInfo` object (from `usePoolInfo`) into `prepareSubmitData` so that `targetPuzzleHash` and `relativeLockHeight` used in the transaction are exactly the values the user reviewed. If a fresh fetch is required for any reason, compare it against the displayed values and abort with an error if they differ.

---

### Proof of Concept

1. Operator runs a pool server that tracks request count per client session.
2. On the **first** `/pool_info` request: return honest data, e.g. `target_puzzle_hash: "0xLEGIT..."`, `relative_lock_height: 32`, `fee: "0.01"`.
3. On the **second** `/pool_info` request (triggered by form submission): return `target_puzzle_hash: "0xATTACKER..."`, `relative_lock_height: 4608`.
4. User enters the pool URL → sees the honest pool info rendered by `<PoolInfo>` in `PlotNFTSelectBase`.
5. User clicks "Create" / "Change".
6. `prepareSubmitData` fires, calls `getPoolInfo` a second time, receives the malicious response.
7. `pwJoinPool` is called with `targetPuzzlehash: "0xATTACKER..."` and `relativeLockHeight: 4608`.
8. The Plot NFT is written on-chain with the attacker's puzzle hash. All 7/8 block rewards flow to the attacker's address. The user is locked in for ~4608 blocks (~1 day) instead of the displayed ~32 blocks (~5 minutes).

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx (L27-39)
```typescript
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
```

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx (L39-39)
```typescript
  const poolInfo = usePoolInfo(poolUrl);
```

**File:** packages/gui/src/hooks/usePoolInfo.ts (L47-56)
```typescript
    try {
      const data = await getPoolInfo(normalizedUrl);

      return {
        poolUrl: normalizedUrl,
        ...data,
      };
    } catch (e) {
      throw new Error(t`The pool URL "${normalizedUrl}" is not working. Is it pool? Error: ${e.message}`);
    }
```

**File:** packages/gui/src/electron/main.tsx (L492-495)
```typescript
    ipcMainHandle(AppAPI.FETCH_POOL_INFO, async (poolUrl: string) => {
      const poolInfoUrl = `${poolUrl}/pool_info`;
      return fetchJSON(poolInfoUrl);
    });
```

**File:** packages/gui/src/util/getPoolInfo.ts (L4-6)
```typescript
export default async function getPoolInfo(poolUrl: string): Promise<PoolInfo> {
  const data = await window.appAPI.fetchPoolInfo(poolUrl);
  return toCamelCase(data) as PoolInfo;
```
