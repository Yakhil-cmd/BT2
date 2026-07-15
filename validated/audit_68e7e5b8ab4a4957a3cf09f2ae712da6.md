The code confirms a real double-fetch TOCTOU vulnerability. Here is the full analysis:

---

### Title
TOCTOU: Malicious Pool Server Can Substitute `targetPuzzleHash` Between Preview and Submit, Redirecting Farming Rewards — (`packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx`)

### Summary

`PlotNFTSelectPool` makes two independent HTTP fetches to the pool's `/pool_info` endpoint: one for the UI preview and a second one at submit time inside `prepareSubmitData`. A pool server that returns different `targetPuzzleHash` values in each response can cause `pwJoinPool` to be called with an attacker-controlled puzzle hash while the user sees a legitimate one in the confirmation UI.

### Finding Description

**Fetch 1 — preview display:**
`PlotNFTSelectBase` calls `usePoolInfo(poolUrl)` reactively as the user types the URL. [1](#0-0) 

`usePoolInfo` calls `getPoolInfo(normalizedUrl)` and the result (including `targetPuzzleHash`) is rendered in the `PoolInfo` card for the user to review. [2](#0-1) 

**Fetch 2 — submit time:**
When the user clicks submit, `handleSubmit` calls `prepareSubmitData(data)`, which issues a **second, independent** `getPoolInfo` call to the same URL: [3](#0-2) 

The `targetPuzzleHash` from this second fetch is what is passed directly to `pwJoinPool`: [4](#0-3) 

There is **no comparison** between the two fetches' results. The value shown to the user and the value used in the on-chain transaction are sourced from two separate network round-trips with no binding between them.

### Impact Explanation

A pool operator (or anyone who has compromised a pool server) can:
1. Return `hash_A` (legitimate) on the first `/pool_info` request → user sees and approves it.
2. Return `hash_B` (attacker-controlled) on the second `/pool_info` request triggered at submit time.
3. `pwJoinPool` is called with `hash_B`, directing all future farming rewards to the attacker's address.

The user has no way to detect this substitution because the confirmation UI only ever showed `hash_A`.

### Likelihood Explanation

Any pool operator can trivially implement this server-side. The attack requires no local access, no key compromise, and no social engineering beyond the user choosing to join a pool — which is the normal intended workflow. The window between the two fetches is the time between the preview loading and the user clicking submit, which is always non-zero.

### Recommendation

Bind the preview result to the submit action. Concretely:
- Cache the `poolInfo` result from `usePoolInfo` in form state (e.g., via `react-hook-form` `setValue`) when the preview loads.
- In `prepareSubmitData`, use the cached value instead of re-fetching.
- If a re-fetch is desired for freshness, compare the returned `targetPuzzleHash` against the cached/displayed value and abort with an error if they differ.

### Proof of Concept

1. Stand up an HTTP server at `http://localhost:8080` that serves `/pool_info`:
   - On the **first** request: returns `{ "target_puzzle_hash": "0xAAAA...AAAA", "relative_lock_height": 32, ... }`
   - On the **second** request: returns `{ "target_puzzle_hash": "0xBBBB...BBBB", "relative_lock_height": 32, ... }`
2. Open `PlotNFTChangePool` in the GUI and enter `http://localhost:8080` as the pool URL.
3. Wait for the `PoolInfo` card to render and display `0xAAAA...AAAA`.
4. Click the submit button.
5. Observe that `pwJoinPool` is called with `targetPuzzlehash: "0xBBBB...BBBB"` — the attacker-controlled value — while the user only ever saw `0xAAAA...AAAA`.

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
