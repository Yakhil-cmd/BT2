### Title
Unbounded `reward.stakingrewardthreshold` Governance Parameter Silently Truncated to `uint64`, Corrupting Staking Reward Distribution — (`kaiax/reward/impl/getter.go`)

---

### Summary

The `reward.stakingrewardthreshold` governance parameter is stored as an arbitrary-precision `*big.Int` and its `FormatChecker` only enforces non-negativity. However, in `assignStakingRewardsFlex`, the value is consumed via `config.StakingRewardThreshold.Uint64()`, which silently returns only the low 64 bits of any value exceeding `uint64` max. A governing node that sets this parameter to a value larger than `2^64 − 1` (e.g., by confusing KAIA units with kei units, an 18-decimal-place mistake) causes the threshold used in every subsequent block's staking reward calculation to be a completely different number than intended, permanently redirecting KAIA staking rewards away from eligible validators.

---

### Finding Description

**Governance parameter definition — no upper-bound validation**

In `kaiax/gov/param.go`, `RewardStakingRewardThreshold` is declared with `bigIntCanonicalizer` (accepts any decimal string as `*big.Int`) and a `FormatChecker` that only rejects negative values:

```go
RewardStakingRewardThreshold: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(*big.Int)
        if !ok { return false }
        return v.Sign() >= 0   // ← only non-negativity; no upper bound
    },
    ...
    DefaultValue: big.NewInt(5_000_000),
},
``` [1](#0-0) 

Any non-negative `*big.Int` — including values far exceeding `uint64` max (`~1.84 × 10¹⁹`) — passes validation and is ratified into the governance state.

**Silent truncation at the point of use**

In `assignStakingRewardsFlex`, the stored `*big.Int` is consumed as a plain `uint64`:

```go
func assignStakingRewardsFlex(...) (map[common.Address]*big.Int, *big.Int) {
    var (
        minStake  = config.MinimumStake.Uint64()
        threshold = config.StakingRewardThreshold.Uint64()  // ← silent low-64-bit truncation
        ...
    )
    for _, cn := range cns {
        if cn.StakingAmount < minStake { continue }
        amount := cn.StakingAmount
        if amount > threshold {
            excessInt[cn.RewardAddr] = amount - threshold
            ...
        }
    }
``` [2](#0-1) 

Go's `(*big.Int).Uint64()` returns only the low 64 bits with no error, no panic, and no indication of truncation. The stored governance value and the value actually used in reward arithmetic are silently different.

**Call path into production block finalization**

`assignStakingRewardsFlex` is called from `getDeferredRewardFullFlex`, which is selected whenever `config.Rules.IsOsaka && config.UseFlexReward`:

```go
if config.Rules.IsOsaka && config.UseFlexReward {
    return getDeferredRewardFullFlex(config, execFee, burntFee, blobFee, si)
``` [3](#0-2) 

This is the live Flex reward path introduced at the Osaka hardfork.

**Contrast with `reward.mintingamount`**

`RewardMintingAmount` uses `noopFormatChecker` — literally no validation — and is consumed as `*big.Int` throughout, so an astronomically large value would cause hyperinflation rather than a truncation-induced redistribution. The `stakingrewardthreshold` bug is more insidious because the stored value and the used value silently diverge. [4](#0-3) 

---

### Impact Explanation

When `StakingRewardThreshold` is set to a value V > `uint64` max, `V.Uint64()` returns `V mod 2^64`. Two representative cases:

| Intended V | Truncated result | Effect |
|---|---|---|
| `5_000_000 × 10^18` (kei-unit mistake) | wraps to a small or large unexpected value | Threshold is wrong; reward eligibility is corrupted |
| `2^64 + 2^63` | `2^63 ≈ 9.2 × 10^18` KAIA | No validator's stake exceeds threshold; entire staking-reward budget is redirected to the proposer |
| `2^64` | `0` | Every validator with any stake is eligible; rewards diluted across all |

In the worst case (threshold wraps to a value exceeding total KAIA supply), the entire staking-reward portion of every block's minting reward is permanently redirected to the block proposer instead of being distributed proportionally to stakers. This is an unauthorized redistribution of KAIA from stakers to the proposer on every block for the duration of the epoch.

---

### Likelihood Explanation

The default value is `5_000_000` (KAIA units). The code comment in the README describes the threshold in KAIA units. A governing node operator who mistakenly supplies the value in kei (multiplying by `10^18`) would produce `5 × 10^24`, which exceeds `uint64` max by a factor of ~271,000. The `FormatChecker` accepts it silently. This is the same class of 18-decimal-place mistake described in the external report. The mistake is plausible because:

- The parameter is a `*big.Int` (suggesting arbitrary precision is meaningful)
- No documentation in the `FormatChecker` or error message constrains the unit
- Other KAIA monetary values (e.g., `MintingAmount`) are expressed in kei (`9600000000000000000`)

---

### Recommendation

**Short term**: Add an explicit upper-bound check in the `FormatChecker` for `RewardStakingRewardThreshold` (and `RewardMinimumStake`) that rejects any value exceeding `math.MaxUint64`. Add a corresponding check in `assignStakingRewardsFlex` that panics or returns an error if `StakingRewardThreshold.IsUint64()` returns false before calling `.Uint64()`.

**Long term**: Validate all governance parameters at the point of use, not only at the point of acceptance. Where a `*big.Int` parameter is consumed as `uint64`, the conversion must be guarded. Add unit documentation to every `FormatChecker` that involves a monetary amount, specifying whether the expected unit is KAIA or kei.

---

### Proof of Concept

1. Governing node casts a vote via `governance_vote`:
   ```json
   {"method":"governance_vote","params":["reward.stakingrewardthreshold","5000000000000000000000000"]}
   ```
   Value `5 × 10^24` passes `FormatChecker` (non-negative `*big.Int`). It is ratified at the next epoch boundary.

2. `NewRewardConfig` reads the ratified value:
   ```go
   rc.StakingRewardThreshold = new(big.Int).Set(paramset.StakingRewardThreshold)
   // rc.StakingRewardThreshold = 5000000000000000000000000
   ``` [5](#0-4) 

3. In `assignStakingRewardsFlex`:
   ```go
   threshold = config.StakingRewardThreshold.Uint64()
   // 5000000000000000000000000 mod 2^64 = some unexpected uint64 value
   ``` [6](#0-5) 

4. The `amount > threshold` comparison uses the truncated value. Depending on the truncated result, either all staking rewards are redirected to the proposer (threshold too high) or all validators receive rewards regardless of their stake (threshold = 0). In either case, the `RewardSpec` produced for `FinalizeState` contains incorrect per-address KAIA amounts, and those amounts are credited to the wrong recipients on every block for the remainder of the epoch. [7](#0-6)

### Citations

**File:** kaiax/gov/param.go (L414-424)
```go
	RewardMintingAmount: {
		Canonicalizer: bigIntCanonicalizer,
		FormatChecker: noopFormatChecker,
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil || c.Governance.Reward == nil || c.Governance.Reward.MintingAmount == nil {
				return nil, errors.New("reward is not set")
			}
			return c.Governance.Reward.MintingAmount, nil
		},
		DefaultValue: big.NewInt(0),
	},
```

**File:** kaiax/gov/param.go (L497-515)
```go
	RewardStakingRewardThreshold: {
		Canonicalizer: bigIntCanonicalizer,
		FormatChecker: func(cv any) bool {
			v, ok := cv.(*big.Int)
			if !ok {
				return false
			}
			return v.Sign() >= 0
		},
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			// This parameter may be absent in ChainConfig because it was introduced at Osaka.
			// However, ChainConfig.SetDefaults() should have set it to the default value.
			if c.Governance == nil || c.Governance.Reward == nil || c.Governance.Reward.StakingRewardThreshold == nil {
				return nil, errors.New("reward is not set")
			}
			return c.Governance.Reward.StakingRewardThreshold, nil
		},
		DefaultValue: big.NewInt(5_000_000),
	},
```

**File:** kaiax/reward/impl/getter.go (L289-291)
```go
	if config.Rules.IsOsaka && config.UseFlexReward {
		return getDeferredRewardFullFlex(config, execFee, burntFee, blobFee, si)
	} else if config.Rules.IsKore {
```

**File:** kaiax/reward/impl/getter.go (L423-452)
```go
func assignStakingRewardsFlex(config *reward.RewardConfig, budget *big.Int, si *staking.StakingInfo) (map[common.Address]*big.Int, *big.Int) {
	var (
		minStake  = config.MinimumStake.Uint64()
		threshold = config.StakingRewardThreshold.Uint64()
		isPrague  = config.Rules.IsPrague

		cns            = si.ConsolidatedNodes()
		excessInt      = make(map[common.Address]uint64)
		totalExcessInt = uint64(0)
	)

	// Calculate the excess stakes (the amount over the threshold) for each CN.
	for _, cn := range cns {
		// If the CNStaking is less than minStake, skip it. Even if (CNStaking + CLStaking) could be more than minStake,
		// the CNStaking alone must be at least minStake to be eligible.
		if cn.StakingAmount < minStake {
			continue
		}

		amount := cn.StakingAmount
		if isPrague && cn.CLStakingInfo != nil {
			amount += cn.CLStakingInfo.CLStakingAmount
		}

		// Excess is the amount over the threshold (not over minStake).
		if amount > threshold {
			excessInt[cn.RewardAddr] = amount - threshold
			totalExcessInt += excessInt[cn.RewardAddr]
		}
	}
```

**File:** kaiax/reward/config.go (L65-65)
```go
	rc.StakingRewardThreshold = new(big.Int).Set(paramset.StakingRewardThreshold)
```
