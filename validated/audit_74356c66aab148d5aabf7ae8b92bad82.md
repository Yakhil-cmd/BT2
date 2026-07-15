The TOCTOU race is real and concrete. Here is the analysis:

---

### Title
Pool `targetPuzzleHash` TOCTOU: Display Fetch vs. Submit Fetch Use Different HTTP Responses — (`packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx`)

### Summary

The "Verify Pool Details" display and the actual `pw_join_pool` submission use **two independent HTTP requests** to the pool server. A malicious pool operator can serve a benign `targetPuzzleHash` to the display request and an attacker-controlled `targetPuzzleHash` to the submit-time request, causing the user's farming rewards to flow to the attacker's puzzle hash while the UI showed a legitimate one.

### Finding Description

`PlotNFTSelectBase.tsx` line 39 calls `usePoolInfo(poolUrl)`, which internally calls `getPoolInfo(normalizedUrl)` → `window.appAPI.fetchPoolInfo(poolUrl)`. The result is rendered in the "Verify Pool Details" panel. [1](#0-0) [2](#0-1) 

When the user clicks submit, `prepareSubmitData` in `PlotNFTSelectPool.tsx` makes a **completely separate, independent** call to `getPoolInfo(normalizedPoolUrl)` at line 29, and uses the `targetPuzzleHash` from *that* response — not from the one already displayed to the user. [3](#0-2) 

There is no code anywhere that compares the `targetPuzzleHash` returned at submit time against the one previously fetched and displayed. The displayed value from `usePoolInfo` is never stored in form state, never passed to `prepareSubmitData`, and never validated against the submit-time fetch result. [4](#0-3) 

### Impact Explanation

The `targetPuzzleHash` placed into `initialTargetState` at submit time is what gets submitted to `pw_join_pool`. If the pool server returns a different puzzle hash on the second request, the user's plot NFT is configured to send all farming rewards to the attacker's address, while the UI showed a legitimate one. This is a direct, irreversible misdirection of pooled farming rewards. [5](#0-4) 

### Likelihood Explanation

The attacker only needs to operate a pool server and serve different `/pool_info` responses based on request count or timing. No local access, leaked keys, or cryptographic weakness is required. The user must voluntarily enter the attacker's pool URL, which is a realistic social engineering scenario (e.g., a pool advertised with a slightly lower fee).

### Recommendation

Cache the `targetPuzzleHash` (and all other security-relevant fields) from the display fetch — e.g., store `poolInfo.poolInfo` into form state after the "Verify Pool Details" step resolves — and use that cached value in `prepareSubmitData` instead of making a second independent HTTP request. If a second fetch is made for any reason, assert that `targetPuzzleHash` and `relativeLockHeight` are byte-for-byte identical to the displayed values before proceeding; abort and show an error if they differ.

### Proof of Concept

1. Stand up a pool server at `http://attacker.pool/` that tracks request count per client.
2. On the **first** `/pool_info` request, return `targetPuzzleHash = HASH_A` (a legitimate-looking hash).
3. On the **second** `/pool_info` request, return `targetPuzzleHash = HASH_B` (attacker-controlled address).
4. User opens "Join a Pool", enters `http://attacker.pool/`, waits for the "Verify Pool Details" panel to render showing `HASH_A`.
5. User clicks submit.
6. `prepareSubmitData` fires a new `getPoolInfo` call, receives `HASH_B`, and passes it to `pw_join_pool`.
7. Assert: the `pw_join_pool` RPC call contains `targetPuzzleHash = HASH_B` while the UI displayed `HASH_A`. The user's farming rewards now flow to the attacker. [6](#0-5) [7](#0-6)

### Citations

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx (L39-39)
```typescript
  const poolInfo = usePoolInfo(poolUrl);
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
