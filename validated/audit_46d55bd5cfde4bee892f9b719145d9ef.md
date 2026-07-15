### Title
TOCTOU Race on Pool `targetPuzzleHash` Allows Malicious Pool to Redirect Farming Rewards — (File: `packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx`)

---

### Summary
When a user joins or changes a pool, the GUI fetches pool info **twice** from the external pool server: once to display for user verification, and again at submit time inside `prepareSubmitData`. A malicious pool operator can serve a legitimate `targetPuzzleHash` during the display fetch and a different, attacker-controlled `targetPuzzleHash` during the submit fetch. The value from the submit-time fetch is passed directly to `pwJoinPool` with no consistency check against what the user reviewed, redirecting all pooled farming rewards to the attacker.

---

### Finding Description

The pool-join flow has two independent HTTP fetches to the pool server:

**Fetch 1 — display time** (`usePoolInfo.ts`, line 48):
```ts
const data = await getPoolInfo(normalizedUrl);
```
This result is rendered in `PlotNFTSelectBase` → `PoolInfo` component so the user can "Verify Pool Details," including the displayed `targetPuzzleHash`.

**Fetch 2 — submit time** (`PlotNFTSelectPool.tsx`, line 29):
```ts
const { targetPuzzleHash, relativeLockHeight } = await getPoolInfo(normalizedPoolUrl);
```
This is a completely separate HTTP request made inside `prepareSubmitData` when the user clicks the submit button. The `targetPuzzleHash` from **this** response — not the one the user reviewed — is what gets passed to `pwJoinPool`:

```ts
// PlotNFTChangePool.tsx line 54-60
await pwJoinPool({
  walletId,
  poolUrl,
  relativeLockHeight,
  targetPuzzlehash: targetPuzzleHash,
  fee,
}).unwrap();
```

The only guard on `targetPuzzleHash` is a truthiness check (`if (!targetPuzzleHash)`). There is no format validation, no hex-length check, and no comparison to the value the user saw during verification.

`getPoolInfo` itself performs no validation beyond camelCase conversion:
```ts
// getPoolInfo.ts
const data = await window.appAPI.fetchPoolInfo(poolUrl);
return toCamelCase(data) as PoolInfo;
```

The main-process handler appends `/pool_info` and calls `fetchJSON` with no response validation:
```ts
// main.tsx line 492-495
ipcMainHandle(AppAPI.FETCH_POOL_INFO, async (poolUrl: string) => {
  const poolInfoUrl = `${poolUrl}/pool_info`;
  return fetchJSON(poolInfoUrl);
});
```

---

### Impact Explanation

`targetPuzzleHash` is the on-chain puzzle hash that determines where pooled farming block rewards are paid. By substituting a different value between the display check and the submit use, a malicious pool operator causes the user to sign and broadcast a `pw_join_pool` transaction that permanently assigns their Plot NFT singleton's reward destination to the attacker's address. All future pooled farming rewards (the 7/8 XCH block reward share) flow to the attacker for as long as the NFT remains joined to that pool. This is an unauthorized payout change affecting pooled farming rewards — Critical impact under the allowed scope.

---

### Likelihood Explanation

Any operator of a pool server reachable by the user can exploit this. The user must only type the pool URL and click through the UI. The attacker controls the HTTP response content at both fetch points. The window between the two fetches is the time the user spends reviewing the displayed pool info and clicking submit — typically several seconds, easily exploitable with a server-side flag that switches the response after the first request per IP/session. No leaked keys, host compromise, or cryptographic break is required.

---

### Recommendation

Capture the pool info result from the display-time fetch and pass it through to `prepareSubmitData` rather than re-fetching. The `targetPuzzleHash` and `relativeLockHeight` used to construct the transaction must be the same values the user reviewed. Concretely:

- Store the `poolInfo` returned by `usePoolInfo` in form state or pass it as a parameter to `prepareSubmitData`.
- Remove the second `getPoolInfo` call inside `prepareSubmitData`; use the already-fetched, user-verified values instead.
- Add format validation on `targetPuzzleHash` (64-character lowercase hex string) before passing it to `pwJoinPool`.

---

### Proof of Concept

1. Attacker operates a pool server at `https://evil-pool.example/`.
2. Server logic: on the **first** request to `/pool_info` per session, return `target_puzzle_hash: <legitimate_pool_hash>`. On the **second** request, return `target_puzzle_hash: <attacker_personal_wallet_hash>`.
3. User opens the GUI, navigates to **Join a Pool** or **Change Pool**, enters `https://evil-pool.example/`.
4. `usePoolInfo` fires Fetch 1 → server returns legitimate hash → displayed in "Verify Pool Details."
5. User reviews the displayed hash, sees it looks correct, clicks **Create** / **Change**.
6. `prepareSubmitData` fires Fetch 2 → server returns attacker's hash.
7. `pwJoinPool` is called with `targetPuzzlehash = <attacker_personal_wallet_hash>`.
8. Transaction is signed and broadcast; the Plot NFT singleton now pays all pool rewards to the attacker's address. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** packages/gui/src/hooks/usePoolInfo.ts (L47-53)
```typescript
    try {
      const data = await getPoolInfo(normalizedUrl);

      return {
        poolUrl: normalizedUrl,
        ...data,
      };
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

**File:** packages/gui/src/electron/main.tsx (L492-495)
```typescript
    ipcMainHandle(AppAPI.FETCH_POOL_INFO, async (poolUrl: string) => {
      const poolInfoUrl = `${poolUrl}/pool_info`;
      return fetchJSON(poolInfoUrl);
    });
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

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx (L132-140)
```typescript
      <StyledCollapse in={showPoolInfo}>
        <CardStep step={typeof step === 'number' ? step + 1 : undefined} title={<Trans>Verify Pool Details</Trans>}>
          {poolInfo.error && <Alert severity="warning">{poolInfo.error.message}</Alert>}

          {poolInfo.loading && <Loading center />}

          {poolInfo.poolInfo && <PoolInfo poolInfo={poolInfo.poolInfo} />}
        </CardStep>
      </StyledCollapse>
```
