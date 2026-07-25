### Title
Integer Overflow in `reward.ratio` Governance Validation Bypasses Per-Part Bounds, Enabling Unbounded KAIA Minting — (File: `kaiax/gov/param.go`, `kaiax/reward/config.go`)

---

### Summary

Both the governance `FormatChecker` for `RewardRatio` and `NewRewardRatio` validate only the **aggregate sum** of ratio parts (`sum == 100`) using signed integer arithmetic. Because neither function caps individual parts to `[0, 100]`, a crafted ratio string with two `MaxInt64` components causes the signed-integer sum to wrap around to exactly `100`, bypassing both guards. The resulting `RewardRatio` struct carries `int64` fields of value `9223372036854775807`, which are then passed to `big.NewInt` and multiplied against the minting amount, producing an astronomically large reward allocation every block.

---

### Finding Description

**Location 1 — `FormatChecker` in `kaiax/gov/param.go` lines 464–476:**

```go
sum := 0
for _, part := range parts {
    num, err := strconv.Atoi(part)   // int (64-bit on 64-bit platforms)
    if err != nil { return false }
    if num < 0 { return false }
    sum += num                        // ← signed overflow, no guard
}
return sum == 100
```

`strconv.Atoi("9223372036854775807")` succeeds on 64-bit platforms (returns `MaxInt64`). Adding two `MaxInt64` values to `sum` wraps to `-2`; adding `51 + 51` yields exactly `100`. The format check returns `true`.

**Location 2 — `NewRewardRatio` in `kaiax/reward/config.go` lines 98–109:**

```go
g, err1 := strconv.ParseInt(parts[0], 10, 64)   // g = MaxInt64
x, err2 := strconv.ParseInt(parts[1], 10, 64)   // x = MaxInt64
y, err3 := strconv.ParseInt(parts[2], 10, 64)   // y = 51
z, err4 := strconv.ParseInt(parts[3], 10, 64)   // z = 51
if ... || g+x+y+z != 100 || g < 0 || x < 0 || y < 0 || z < 0 {
    return nil, errMalformedRewardRatio(ratio)
}
return &RewardRatio{g: g, x: x, y: y, z: z}, nil
```

`g+x` = `MaxInt64 + MaxInt64` = `-2` in `int64` arithmetic. `-2 + 51 + 51 = 100`. All negativity checks pass. A `RewardRatio` with `g = x = 9223372036854775807` is returned.

**Location 3 — `SplitFlex` in `kaiax/reward/config.go` lines 130–142:**

```go
gAmount := new(big.Int).Mul(amount, big.NewInt(r.g))   // amount × MaxInt64
gAmount  = gAmount.Div(gAmount, big100)
```

With `mintingAmount = 9_600_000_000_000_000_000` (9.6 KAIA):

```
gAmount ≈ 9.6e18 × 9.22e18 / 100 ≈ 8.85 × 10^35 wei
```

This amount is credited to the validator/proposer address via `AddBalance` every block.

---

### Impact Explanation

Every block after the malicious governance parameter takes effect, `FinalizeState` calls `getDeferredRewardFullFlex` (or the Kore/pre-Magma equivalents), which calls `SplitFlex`/`Split` with the corrupted ratio. The result is that the proposer and fund addresses receive `~8.85 × 10^35 wei` per block instead of the intended fraction of the minting amount. This constitutes **unauthorized minting of KAIA** at a rate that would exhaust any conceivable supply within a single block, corrupting the canonical state and breaking all downstream accounting (total supply, staking rewards, fund balances).

---

### Likelihood Explanation

In `governance.governancemode = "none"` (any GC member may vote; last vote in the epoch is ratified), a **single** GC member can submit the malicious `reward.ratio` string via the `governance_vote` RPC. No majority collusion is required. The vote passes `NewVoteData` → `FormatChecker` (overflow bypass), is inscribed in `header.Vote`, ratified at the next epoch block, and then applied via `NewRewardRatio` (same overflow bypass) to every subsequent block's reward calculation.

On Kaia Mainnet, `single` mode is used (only the governing node may vote), which raises the bar to a single privileged key compromise. However, the code path is identical and the vulnerability is present in both modes.

---

### Recommendation

1. **Cap individual parts** in both the `FormatChecker` and `NewRewardRatio` before summing:
   ```go
   if num < 0 || num > 100 { return false }
   ```
2. **Use `uint` or `uint64`** for the accumulator in the format checker to eliminate signed-overflow wrapping.
3. **Add a per-field bound check** in `NewRewardRatio`:
   ```go
   if g < 0 || g > 100 || x < 0 || x > 100 || y < 0 || y > 100 || z < 0 || z > 100 {
       return nil, errMalformedRewardRatio(ratio)
   }
   ```

---

### Proof of Concept

**Crafted ratio string:** `"9223372036854775807/9223372036854775807/51/51"`

**Step 1 — Format checker passes (overflow):** [1](#0-0) 

```
sum = 0
sum += 9223372036854775807  → sum = 9223372036854775807
sum += 9223372036854775807  → sum = -2          (int64 wrap)
sum += 51                   → sum = 49
sum += 51                   → sum = 100
sum == 100 → true           ✓ vote accepted
```

**Step 2 — `NewRewardRatio` passes (same overflow):** [2](#0-1) 

```
g = 9223372036854775807, x = 9223372036854775807, y = 51, z = 51
g+x+y+z = -2 + 102 = 100   ✓ no error returned
RewardRatio{g: MaxInt64, x: MaxInt64, y: 51, z: 51} stored
```

**Step 3 — Reward distribution corrupted every block:** [3](#0-2) 

```
gAmount = 9_600_000_000_000_000_000 × 9_223_372_036_854_775_807 / 100
        ≈ 8.85 × 10^35 wei credited to proposer address per block
```

**Step 4 — Governance trigger (none mode):** [4](#0-3) 

Any GC member calls `governance_vote("reward.ratio", "9223372036854775807/9223372036854775807/51/51")`. The vote passes all checks, is inscribed in the next block the member proposes, and is ratified at the epoch boundary. From the next epoch onward, every block mints `~8.85 × 10^35 wei` to the proposer and fund addresses.

### Citations

**File:** kaiax/gov/param.go (L464-476)
```go
			sum := 0
			for _, part := range parts {
				num, err := strconv.Atoi(part)
				if err != nil {
					return false
				}
				if num < 0 {
					return false
				}
				sum += num
			}

			return sum == 100
```

**File:** kaiax/reward/config.go (L98-109)
```go
	g, err1 := strconv.ParseInt(parts[0], 10, 64)
	x, err2 := strconv.ParseInt(parts[1], 10, 64)
	y, err3 := strconv.ParseInt(parts[2], 10, 64)
	z := int64(0)
	var err4 error
	if len(parts) == 4 {
		z, err4 = strconv.ParseInt(parts[3], 10, 64)
	}
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || g+x+y+z != 100 || g < 0 || x < 0 || y < 0 || z < 0 {
		return nil, errMalformedRewardRatio(ratio)
	}
	return &RewardRatio{g: g, x: x, y: y, z: z}, nil
```

**File:** kaiax/reward/config.go (L129-142)
```go
func (r *RewardRatio) SplitFlex(amount *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {
	gAmount := new(big.Int).Mul(amount, big.NewInt(r.g))
	gAmount = gAmount.Div(gAmount, big100)

	xAmount := new(big.Int).Mul(amount, big.NewInt(r.x))
	xAmount = xAmount.Div(xAmount, big100)

	yAmount := new(big.Int).Mul(amount, big.NewInt(r.y))
	yAmount = yAmount.Div(yAmount, big100)

	zAmount := new(big.Int).Mul(amount, big.NewInt(r.z))
	zAmount = zAmount.Div(zAmount, big100)

	return gAmount, xAmount, yAmount, zAmount
```

**File:** kaiax/gov/headergov/impl/api.go (L53-63)
```go
func (api *headerGovAPI) Vote(name string, value any) (string, error) {
	var (
		voter     = api.h.nodeAddress
		nextBlock = api.h.Chain.CurrentBlock().NumberU64() + 1
		gp        = api.h.GetParamSet(nextBlock)
		gMode     = gp.GovernanceMode
	)

	if gMode == "single" && voter != gp.GoverningNode {
		return "", ErrVotePermissionDenied
	}
```
