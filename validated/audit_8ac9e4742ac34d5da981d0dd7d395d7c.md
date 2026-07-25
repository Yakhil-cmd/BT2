### Title
Unbounded `reward.mintingamount` Governance Parameter Enables Arbitrary Per-Block KAIA Inflation — (File: `kaiax/gov/param.go`)

---

### Summary

The `RewardMintingAmount` governance parameter is registered with `noopFormatChecker`, which unconditionally accepts any canonical `*big.Int` value. No upper-bound guard exists anywhere in the vote-validation, consistency-check, or reward-finalization path. A governing node (the sole authorized voter in Mainnet's `single` governance mode) can vote to set `reward.mintingamount` to an arbitrarily large value. Once ratified at the next epoch boundary, every subsequent block mints that amount and credits it to validators and fund addresses via `state.AddBalance`, permanently corrupting the KAIA total supply.

---

### Finding Description

**Root cause — `kaiax/gov/param.go`**

`RewardMintingAmount` is the only `*big.Int`-typed minting parameter and it uses `noopFormatChecker`:

```go
RewardMintingAmount: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: noopFormatChecker,   // always returns true
    ...
},
``` [1](#0-0) 

By contrast, `RewardMinimumStake` — also a `*big.Int` parameter — has an explicit non-negativity guard:

```go
FormatChecker: func(cv any) bool {
    v, ok := cv.(*big.Int)
    ...
    return v.Sign() >= 0
},
``` [2](#0-1) 

The asymmetry is an oversight: `MintingAmount` has no lower-bound check and no upper-bound check.

**No consistency check — `kaiax/gov/headergov/impl/header.go`**

`checkConsistency` explicitly returns `nil` for `RewardMintingAmount` without inspecting the value:

```go
case gov.GovernanceDeriveShaImpl, ..., gov.RewardMintingAmount, ...:
    return nil
``` [3](#0-2) 

**No upper-bound guard in `RewardSpec.Validate()` — `kaiax/reward/spec.go`**

The only validation performed before distributing rewards is a negativity check on each recipient amount:

```go
func (spec *RewardSpec) Validate() error {
    for addr, amount := range spec.Rewards {
        if amount.Sign() < 0 {
            return errNegativeRewardAmount(addr, amount)
        }
    }
    return nil
}
``` [4](#0-3) 

An astronomically large positive `MintingAmount` produces large positive per-recipient amounts, which pass this check.

**Unbounded minting at block finalization — `kaiax/reward/impl/blockstate.go`**

`FinalizeState` calls `GetDeferredReward`, which sets `minted = config.MintingAmount` and distributes it to all recipients:

```go
spec, err := r.GetDeferredReward(header, txs, receipts)
...
for addr, amount := range spec.Rewards {
    state.AddBalance(addr, amount)
}
``` [5](#0-4) 

`config.MintingAmount` is read directly from `GetParamSet(blockNum).MintingAmount` with no clamping:

```go
rc.MintingAmount = new(big.Int).Set(paramset.MintingAmount)
``` [6](#0-5) 

---

### Impact Explanation

Setting `reward.mintingamount` to `2^255` (a valid `*big.Int` string) causes every block to call `state.AddBalance(proposerAddr, 2^255)`, `state.AddBalance(kifAddr, 2^255 * ratio)`, etc. This:

- Permanently corrupts the KAIA total supply tracked by `kaiax/supply`
- Distributes unbounded KAIA to validator reward addresses and fund addresses (KIF, KEF, KPF) every block
- Constitutes unauthorized KAIA minting affecting system-managed funds

The corrupted state root is committed to the canonical chain and propagated to all nodes, making the impact irreversible without a hard fork.

---

### Likelihood Explanation

Mainnet operates in `single` governance mode with one governing node (`0x52d41ca72af615a1ac3301b0a93efa222ecc7541`). Exploitation requires that node to cast a malicious vote — either through key compromise or insider action. Likelihood is low but non-zero, and the protocol should not rely solely on the governing node's good behavior for a parameter with unbounded impact on token supply.

---

### Recommendation

Add an upper-bound `FormatChecker` for `RewardMintingAmount`, analogous to the existing check on `RewardMinimumStake`:

```go
RewardMintingAmount: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(*big.Int)
        if !ok {
            return false
        }
        // Non-negative and at most, e.g., 1000 KAIA per block
        maxMint := new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
        return v.Sign() >= 0 && v.Cmp(maxMint) <= 0
    },
    ...
},
```

Additionally, add a corresponding bounds check in `checkConsistency` in `kaiax/gov/headergov/impl/header.go` so that a vote for an out-of-range `MintingAmount` is rejected at vote-verification time, before it can be ratified.

---

### Proof of Concept

1. Governing node calls `governance_vote("reward.mintingamount", "57896044618658097711785492504343953926634992332820282019728792003956564819967")` (i.e., `2^255 - 1`).
2. The vote passes `NewVoteData` → `bigIntCanonicalizer` (valid decimal string) → `noopFormatChecker` (always `true`).
3. `VerifyVote` calls `checkConsistency`, which returns `nil` for `RewardMintingAmount` unconditionally.
4. At the next epoch block `k*epoch`, the vote is ratified and written to `header.Governance`.
5. From block `(k+1)*epoch` onward, `GetParamSet(N).MintingAmount = 2^255 - 1`.
6. Each block's `FinalizeState` → `GetDeferredReward` → `getDeferredRewardSimple/Full` sets `minted = 2^255 - 1`.
7. `RewardSpec.Validate()` passes (all amounts are positive).
8. `state.AddBalance(proposerAddr, ~2^255 * rewardRatio)` is called every block, minting unbounded KAIA and permanently corrupting the canonical state root.

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

**File:** kaiax/gov/param.go (L425-433)
```go
	RewardMinimumStake: {
		Canonicalizer: bigIntCanonicalizer,
		FormatChecker: func(cv any) bool {
			v, ok := cv.(*big.Int)
			if !ok {
				return false
			}
			return v.Sign() >= 0
		},
```

**File:** kaiax/gov/headergov/impl/header.go (L205-211)
```go
	case gov.GovernanceDeriveShaImpl, gov.GovernanceGovParamContract, gov.GovernanceGovernanceMode, gov.GovernanceUnitPrice,
		gov.IstanbulCommitteeSize, gov.IstanbulEpoch, gov.IstanbulPolicy,
		gov.Kip71BaseFeeDenominator, gov.Kip71GasTarget, gov.Kip71MaxBlockGasUsedForBaseFee,
		gov.RewardDeferredTxFee, gov.RewardKip82Ratio, gov.RewardMintingAmount, gov.RewardMinimumStake,
		gov.RewardProposerUpdateInterval, gov.RewardRatio, gov.RewardStakingRewardThreshold,
		gov.RewardStakingUpdateInterval, gov.RewardUseFlexReward, gov.RewardUseGiniCoeff:
		return nil
```

**File:** kaiax/reward/spec.go (L118-125)
```go
func (spec *RewardSpec) Validate() error {
	for addr, amount := range spec.Rewards {
		if amount.Sign() < 0 {
			return errNegativeRewardAmount(addr, amount)
		}
	}
	return nil
}
```

**File:** kaiax/reward/impl/blockstate.go (L46-56)
```go
	spec, err := r.GetDeferredReward(header, txs, receipts)
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
	return nil
```

**File:** kaiax/reward/config.go (L62-62)
```go
	rc.MintingAmount = new(big.Int).Set(paramset.MintingAmount)
```
