### Title
Dual-fetch TOCTOU in pool join: display and signing use independent `/pool_info` fetches, allowing a malicious pool to swap `targetPuzzleHash` between review and submission — (`packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx`)

---

### Summary

The pool-join flow makes **two independent HTTP requests** to the pool's `/pool_info` endpoint: one for display (via `usePoolInfo` in `PlotNFTSelectBase`) and a second one at submit time (via `prepareSubmitData`). A malicious pool operator can serve a legitimate-looking `target_puzzle_hash` in the first response (what the user reviews) and an attacker-controlled hash in the second response (what is actually signed and sent to `pwJoinPool`). The user's farming rewards are then redirected to the attacker's address.

---

### Finding Description

**Fetch #1 — display only:**

`PlotNFTSelectBase` calls `usePoolInfo(poolUrl)`, which internally calls `getPoolInfo` → `window.appAPI.fetchPoolInfo(poolUrl)`. The result is rendered in `<PoolInfo poolInfo={poolInfo.poolInfo} />` for the user to review. [1](#0-0) [2](#0-1) 

`usePoolInfo` uses `useAsync` and fires when `poolUrl` changes — it is a reactive hook, not a cached store shared with the submit path. [3](#0-2) 

**Fetch #2 — submit path (independent):**

When the user clicks submit, `handleSubmit` calls `prepareSubmitData(data)`, which makes its own separate call to `getPoolInfo(normalizedPoolUrl)`. The `targetPuzzleHash` returned by **this second fetch** is what gets passed directly to `pwJoinPool`. [4](#0-3) 

`getPoolInfo` is a thin wrapper with no caching — every call is a fresh HTTP request: [5](#0-4) 

**The signing call uses the second fetch's value, not the displayed value:**

In `PlotNFTChangePool.handleSubmit`, `targetPuzzleHash` from `prepareSubmitData` is passed directly as `targetPuzzlehash` to `pwJoinPool` with no comparison against what was shown to the user. [6](#0-5) 

There is **no cross-validation** between the value displayed (fetch #1) and the value signed (fetch #2).

---

### Impact Explanation

`targetPuzzleHash` is the pool's payout puzzle hash — the on-chain address to which the pool sends the farmer's XCH rewards. By serving a different hash in the second response, the attacker redirects all future farming rewards to their own wallet. The user has no indication anything went wrong: the UI showed a legitimate hash, the transaction was submitted normally, and the NFT now points to the attacker's address.

This is a direct, irreversible financial loss of XCH farming rewards.

---

### Likelihood Explanation

Any operator of a pool server (the exact attacker model stated in the question) can implement this trivially: serve the real `target_puzzle_hash` on the first request and an attacker-controlled hash on the second. The two requests are distinguishable by timing (the second arrives only when the user clicks submit) or by a simple request counter. No special access, leaked keys, or local compromise is required.

---

### Recommendation

The fix is to use the **already-fetched** pool info from `usePoolInfo` as the authoritative source for submission, rather than re-fetching. Concretely:

- Pass the `poolInfo` object (already held in `PlotNFTSelectBase`/`usePoolInfo`) up to `PlotNFTSelectPool` via form state or a ref/callback.
- In `prepareSubmitData` (or `handleSubmit`), read `targetPuzzleHash` and `relativeLockHeight` from that cached object instead of calling `getPoolInfo` again.
- If a second fetch is considered necessary for freshness, compare its `targetPuzzleHash` against the displayed value and abort with an error if they differ.

---

### Proof of Concept

```
1. Stand up a pool server that counts requests to /pool_info.
   - Request 1: return { target_puzzle_hash: "0xLEGIT...", relative_lock_height: 100, ... }
   - Request 2+: return { target_puzzle_hash: "0xATTACKER...", relative_lock_height: 100, ... }

2. In the Chia GUI, navigate to change-pool for any PlotNFT.

3. Enter the malicious pool URL. The UI fetches /pool_info (request 1) and displays
   "0xLEGIT..." in the PoolInfo card.

4. User reviews the displayed hash and clicks submit.

5. prepareSubmitData fires, calls getPoolInfo again (request 2), receives "0xATTACKER...".

6. pwJoinPool is called with targetPuzzlehash = "0xATTACKER...".

7. Assert: the hash passed to pwJoinPool ("0xATTACKER...") differs from the hash
   shown in the UI ("0xLEGIT..."). The NFT's payout destination is now the attacker's address.
```

### Citations

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx (L39-39)
```typescript
  const poolInfo = usePoolInfo(poolUrl);
```

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx (L138-138)
```typescript
          {poolInfo.poolInfo && <PoolInfo poolInfo={poolInfo.poolInfo} />}
```

**File:** packages/gui/src/hooks/usePoolInfo.ts (L18-57)
```typescript
  const poolInfo = useAsync(async () => {
    if (isMainnet === undefined) {
      return undefined;
    }

    if (!poolUrl) {
      return undefined;
    }

    const isUrlOptions = {
      allow_underscores: true,
      require_valid_protocol: true,
    };

    if (isMainnet) {
      isUrlOptions.protocols = ['https'];
    }

    const normalizedUrl = normalizeUrl(poolUrl);
    const isValidUrl = isValidURL(normalizedUrl, isUrlOptions);

    if (!isValidUrl) {
      if (isMainnet && !normalizedUrl.startsWith('https:')) {
        throw new Error(t`The pool URL needs to use protocol https. ${normalizedUrl}`);
      }

      throw new Error(t`The pool URL is not valid. ${normalizedUrl}`);
    }

    try {
      const data = await getPoolInfo(normalizedUrl);

      return {
        poolUrl: normalizedUrl,
        ...data,
      };
    } catch (e) {
      throw new Error(t`The pool URL "${normalizedUrl}" is not working. Is it pool? Error: ${e.message}`);
    }
  }, [poolUrl, isMainnet]);
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

**File:** packages/gui/src/util/getPoolInfo.ts (L4-6)
```typescript
export default async function getPoolInfo(poolUrl: string): Promise<PoolInfo> {
  const data = await window.appAPI.fetchPoolInfo(poolUrl);
  return toCamelCase(data) as PoolInfo;
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
