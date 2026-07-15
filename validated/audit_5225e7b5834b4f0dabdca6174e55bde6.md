The TOCTOU is real and concrete. Let me trace the two independent fetches:

**Fetch 1 (display):** `PlotNFTSelectBase.tsx` line 39 calls `usePoolInfo(poolUrl)`, which internally calls `getPoolInfo(normalizedUrl)` → `window.appAPI.fetchPoolInfo(poolUrl)`. The returned `targetPuzzleHash` is rendered in the "Verify Pool Details" panel. [1](#0-0) [2](#0-1) 

**Fetch 2 (submit):** `prepareSubmitData` in `PlotNFTSelectPool.tsx` line 29 makes a **completely independent** second call to `getPoolInfo(normalizedPoolUrl)`. The `targetPuzzleHash` from this second response is what gets submitted to `pw_join_pool`. [3](#0-2) 

Both paths resolve through the same `getPoolInfo` utility: [4](#0-3) 

There is **no caching, no binding, and no comparison** between the `targetPuzzleHash` displayed to the user and the one submitted. The displayed value from Fetch 1 is never stored and reused at submit time — `prepareSubmitData` always re-fetches independently.

---

### Title
TOCTOU Race in Pool Join: Displayed `targetPuzzleHash` Differs from Submitted One — (`packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx`)

### Summary
A malicious pool operator can serve a benign `targetPuzzleHash` on the first `/pool_info` request (shown in "Verify Pool Details") and a different attacker-controlled `targetPuzzleHash` on the second request (used in `pw_join_pool` at submit time), causing farming rewards to flow to the attacker's address while the UI displayed a legitimate one.

### Finding Description
`PlotNFTSelectBase` calls `usePoolInfo(poolUrl)` reactively to display pool details. When the user clicks submit, `prepareSubmitData` independently calls `getPoolInfo(normalizedPoolUrl)` again. These are two separate HTTP requests to the pool server with no mechanism to ensure they return the same data. The `targetPuzzleHash` from the display fetch is discarded; only the submit-time fetch result is used. [5](#0-4) 

### Impact Explanation
`targetPuzzleHash` is the puzzle hash to which all pool farming rewards are paid. If the attacker substitutes their own puzzle hash at submit time, every block reward earned by the user's plots flows to the attacker's wallet. This is a direct, ongoing financial loss affecting pooled farming rewards — a Critical/High impact per scope rules.

### Likelihood Explanation
The precondition is that the user enters the attacker's pool URL, which is a normal user action (not phishing). The attacker is the pool operator — a legitimate threat model for this workflow. The server-side implementation is trivial: track request count per IP and return hash A on request 1, hash B on request 2. No cryptographic break or local compromise is required.

### Recommendation
Cache the `poolInfo` result from the display fetch (e.g., in React form state or a ref) and reuse it in `prepareSubmitData` instead of re-fetching. Specifically, store `poolInfo.targetPuzzleHash` and `poolInfo.relativeLockHeight` into the form values after the display fetch resolves, and read them from form state at submit time — eliminating the second network request entirely.

### Proof of Concept
1. Stand up a pool server that returns `targetPuzzleHash = "0xAAAA..."` on the first `/pool_info` request and `targetPuzzleHash = "0xBBBB..."` on all subsequent requests.
2. Render `PlotNFTSelectPool`, enter the malicious pool URL, and wait for the "Verify Pool Details" panel to display `0xAAAA...`.
3. Click submit.
4. Assert that the `pw_join_pool` RPC call receives `initialTargetState.targetPuzzleHash = "0xBBBB..."` while the UI showed `0xAAAA...`.

The gap between step 2 and step 4 is the TOCTOU window — any delay between display and submit (user reading the details) is sufficient.

### Citations

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx (L39-39)
```typescript
  const poolInfo = usePoolInfo(poolUrl);
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
