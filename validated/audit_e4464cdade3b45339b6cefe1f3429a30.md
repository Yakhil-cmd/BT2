### Title
Malicious Pool Server Can Redirect Farming Rewards via `toCamelCase` Key Collision in `/pool_info` Response — (`packages/gui/src/util/getPoolInfo.ts`, `packages/api/src/utils/toCamelCase.ts`)

---

### Summary

A malicious pool operator can craft a `/pool_info` JSON response containing both the snake_case key `target_puzzle_hash` and the camelCase key `targetPuzzleHash`. When `toCamelCase` processes this response, lodash `transform` iterates keys in insertion order, and the second assignment to the same output key overwrites the first. By placing `targetPuzzleHash` after `target_puzzle_hash` in the JSON, the attacker's puzzle hash wins. `prepareSubmitData` then uses this overwritten value as the farming rewards destination in `pwJoinPool` / `createNewPoolWallet`, redirecting all pooled farming rewards to the attacker.

---

### Finding Description

**Step 1 — Fetch and transform:**

`getPoolInfo` fetches raw JSON from the pool server and immediately applies `toCamelCase`: [1](#0-0) 

`toCamelCase` (from `@chia-network/api`) uses lodash `transform`, which iterates object keys in insertion order: [2](#0-1) 

When the pool response contains both `"target_puzzle_hash"` and `"targetPuzzleHash"` as distinct JSON keys:
- Iteration 1: key `target_puzzle_hash` → `camelCase(key)` → `targetPuzzleHash` → `acc["targetPuzzleHash"] = legitimate_value`
- Iteration 2: key `targetPuzzleHash` → no underscore, kept as-is → `acc["targetPuzzleHash"] = attacker_value` **(overwrites)**

The attacker controls the pool server and therefore controls key ordering in the JSON response.

**Step 2 — Collision value used directly as spend destination:**

`prepareSubmitData` destructures `targetPuzzleHash` from the `toCamelCase` output and places it into `initialTargetState` with no format or origin validation beyond a truthiness check: [3](#0-2) 

**Step 3 — Passed to wallet daemon:**

For pool changes, `targetPuzzleHash` is passed directly as `targetPuzzlehash` to `pwJoinPool`: [4](#0-3) 

For new pool NFTs, `initialTargetState` (containing the attacker's `targetPuzzleHash`) is passed to `createNewPoolWallet`: [5](#0-4) 

**Step 4 — IPC fetch returns raw, untransformed JSON:**

The main process `FETCH_POOL_INFO` handler calls `fetchJSON` with no sanitization or key filtering: [6](#0-5) 

`fetchJSON` returns the parsed JSON object verbatim: [7](#0-6) 

---

### Impact Explanation

The attacker's puzzle hash is used as the `target_puzzle_hash` in the pool join spend bundle. All farming rewards from the user's plots are paid to the attacker's address. This is a direct, irreversible redirection of pooled farming rewards (XCH) — a Critical impact under the scope rules.

---

### Likelihood Explanation

The attacker only needs to operate a web server that returns a crafted `/pool_info` response. No special access, leaked keys, or local compromise is required. The user only needs to enter the malicious pool URL and click "Join Pool." There is no confirmation dialog that shows the raw `targetPuzzleHash` value in a way that would alert the user, and no format validation (e.g., hex length, `0x` prefix check) that would reject an arbitrary attacker-controlled string.

---

### Recommendation

1. In `getPoolInfo`, extract `target_puzzle_hash` from the **raw** (pre-`toCamelCase`) response before transformation, or explicitly allowlist only the expected snake_case keys from the pool info response before passing to `toCamelCase`.
2. Add format validation on `targetPuzzleHash` (e.g., must be a 64-character hex string, optionally `0x`-prefixed) before it is accepted into `initialTargetState`.
3. Consider stripping any keys from the `/pool_info` response that are not in the canonical `PoolInfo` schema before transformation.

---

### Proof of Concept

**Unit test for the collision (locally reproducible):**

```ts
import toCamelCase from '@chia-network/api/src/utils/toCamelCase';

const maliciousPoolInfoResponse = {
  name: "Legit Pool",
  description: "A pool",
  pool_url: "https://evil.pool",
  fee: "0.01",
  logo_url: "https://evil.pool/logo.png",
  minimum_difficulty: 1,
  protocol_version: "1.0",
  relative_lock_height: 32,
  target_puzzle_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  // attacker-injected camelCase key placed AFTER snake_case key:
  targetPuzzleHash: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
};

const result = toCamelCase(maliciousPoolInfoResponse);
// result.targetPuzzleHash === "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
// The attacker's value wins.
```

**End-to-end:**
1. Stand up a server at `http://evil.pool/pool_info` returning the above JSON.
2. In the Chia GUI, navigate to Pool → Add a Plot NFT → enter `http://evil.pool` as the pool URL.
3. Click Create. Observe that the `pw_join_pool` / `create_new_wallet` RPC is called with `targetPuzzlehash = 0xdeadbeef...` (attacker's address) instead of the legitimate `0xaaaa...` value.
4. All farming rewards from the joined plots are paid to the attacker's puzzle hash.

### Citations

**File:** packages/gui/src/util/getPoolInfo.ts (L4-6)
```typescript
export default async function getPoolInfo(poolUrl: string): Promise<PoolInfo> {
  const data = await window.appAPI.fetchPoolInfo(poolUrl);
  return toCamelCase(data) as PoolInfo;
```

**File:** packages/api/src/utils/toCamelCase.ts (L3-8)
```typescript
export default function toCamelCase(object: Object): { [key: string]: unknown } {
  return transform(object, (acc, value, key, target) => {
    const newKey = isArray(target) || key.indexOf('_') === -1 ? key : camelCase(key);

    acc[newKey] = isObject(value) ? toCamelCase(value) : value;
  });
```

**File:** packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx (L29-39)
```typescript
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

**File:** packages/gui/src/components/plotNFT/PlotNFTAdd.tsx (L30-33)
```typescript
    const { transaction } = await createNewPoolWallet({
      initialTargetState,
      fee,
    }).unwrap();
```

**File:** packages/gui/src/electron/main.tsx (L492-495)
```typescript
    ipcMainHandle(AppAPI.FETCH_POOL_INFO, async (poolUrl: string) => {
      const poolInfoUrl = `${poolUrl}/pool_info`;
      return fetchJSON(poolInfoUrl);
    });
```

**File:** packages/gui/src/electron/utils/fetchJSON.ts (L83-86)
```typescript
      response.on('end', () => {
        try {
          const parsedData = JSON.parse(data);
          handleResolve(parsedData);
```
