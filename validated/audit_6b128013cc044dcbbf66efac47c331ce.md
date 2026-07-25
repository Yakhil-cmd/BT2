### Title
Unbounded `reward.mintingamount` Governance Parameter Allows Arbitrary KAIA Minting Per Block — (`kaiax/gov/param.go`, `kaiax/reward/impl/blockstate.go`)

---

### Summary

The `reward.mintingamount` governance parameter is registered with `noopFormatChecker`, meaning no upper-bound validation is applied when a governing node votes to change it. Because `FinalizeState` directly calls `state.AddBalance` using the minted amount derived from this parameter every block, a governing node can set an arbitrarily large minting amount and cause unbounded KAIA inflation per block.

---

### Finding Description

In `kaiax/gov/param.go`, the `RewardMintingAmount` parameter entry uses `noopFormatChecker`:

```go
RewardMintingAmount: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: noopFormatChecker,   // ← always returns true; no upper bound
    ...
}
``` [1](#0-0) 

The `noopFormatChecker` is defined as:

```go
func noopFormatChecker(cv any) bool {
    return true
}
``` [2](#0-1) 

The `bigIntCanonicalizer` only converts the input to a `*big.Int` without any magnitude check: [3](#0-2) 

The vote consistency checker in `kaiax/gov/headergov/impl/header.go` explicitly returns `nil` (no error) for `RewardMintingAmount` without any additional bounds check:

```go
case gov.GovernanceDeriveShaImpl, ..., gov.RewardMintingAmount, ...:
    return nil
``` [4](#0-3) 

Once ratified, the parameter flows into `NewRewardConfig` and is stored as `config.MintingAmount`: [5](#0-4) 

Every block, `FinalizeState` calls `GetDeferredReward`, which sets `minted = new(big.Int).Set(config.MintingAmount)` and distributes it via `state.AddBalance`: [6](#0-5) [7](#0-6) 

The only post-calculation guard is `spec.Validate()`, which only rejects negative amounts — not excessively large ones: [8](#0-7) 

---

### Impact Explanation

A governing node can vote to set `reward.mintingamount` to an arbitrarily large `*big.Int` value (e.g., `2^255`). After the epoch boundary, every subsequent block will call `state.AddBalance` with that value for the proposer, KIF, KEF, and KPF addresses. This directly and permanently inflates the KAIA native token supply without limit, diluting all existing holders. The corrupted state value is the KAIA balance of reward recipients, which grows by the unbounded minting amount every block.

---

### Likelihood Explanation

In `single` governance mode (Mainnet and Kairos), only the designated governing node can vote. This is a semi-trusted actor analogous to the admin in the original M-11 finding. The risk arises from either an accidental misconfiguration (e.g., entering a value in wei instead of KAIA, off by 18 orders of magnitude) or an intentional governance attack. In `none` mode, any GC member can vote, broadening the attack surface further.

---

### Recommendation

Add an explicit upper-bound check in the `FormatChecker` for `RewardMintingAmount`. A reasonable cap (e.g., the current mainnet value of `9.6e18` wei multiplied by a safety factor, or a hard cap such as `1e27` wei) should be enforced:

```go
RewardMintingAmount: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(*big.Int)
        if !ok || v.Sign() < 0 {
            return false
        }
        // e.g., cap at 1e27 wei (1 billion KAIA per block)
        maxMinting, _ := new(big.Int).SetString("1000000000000000000000000000", 10)
        return v.Cmp(maxMinting) <= 0
    },
    ...
}
``` [1](#0-0) 

---

### Proof of Concept

1. The governing node calls `governance_vote("reward.mintingamount", "999999999999999999999999999999999999999")` via the JSON-RPC API.
2. The vote passes `bigIntCanonicalizer` (valid big.Int) and `noopFormatChecker` (always true). [9](#0-8) 
3. `VerifyVote` → `checkConsistency` returns `nil` for `RewardMintingAmount` with no further check. [4](#0-3) 
4. At the next epoch block, the vote is ratified and written to `header.Governance`.
5. Starting from `(k+1)*epoch`, `GetParamSet` returns the new minting amount. `NewRewardConfig` sets `rc.MintingAmount` to the huge value. [10](#0-9) 
6. Every block, `FinalizeState` → `getDeferredRewardFull*` sets `minted = new(big.Int).Set(config.MintingAmount)` and distributes it to all reward recipients via `state.AddBalance`. [7](#0-6) 
7. `spec.Validate()` passes because all amounts are positive. The KAIA balances of the proposer, KIF, KEF, and KPF addresses are inflated by the unbounded amount every block, permanently corrupting the native token supply.

### Citations

**File:** kaiax/gov/param.go (L94-112)
```go
	bigIntCanonicalizer canonicalizerT = func(v any) (any, error) {
		switch v := v.(type) {
		case []byte:
			cv, ok := new(big.Int).SetString(string(v), 10)
			if !ok {
				return nil, ErrCanonicalizeByteToBigInt
			}
			return cv, nil
		case string:
			cv, ok := new(big.Int).SetString(v, 10)
			if !ok {
				return nil, ErrCanonicalizeStringToBigInt
			}
			return cv, nil
		case *big.Int:
			return v, nil
		}
		return nil, ErrCanonicalizeBigInt
	}
```

**File:** kaiax/gov/param.go (L160-162)
```go
func noopFormatChecker(cv any) bool {
	return true
}
```

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

**File:** kaiax/reward/config.go (L59-66)
```go
	paramset := govModule.GetParamSet(header.Number.Uint64())
	rc.IsSimple = paramset.ProposerPolicy != uint64(istanbul.WeightedRandom)
	rc.UnitPrice = new(big.Int).SetUint64(paramset.UnitPrice)
	rc.MintingAmount = new(big.Int).Set(paramset.MintingAmount)
	rc.MinimumStake = new(big.Int).Set(paramset.MinimumStake)
	rc.DeferredTxFee = paramset.DeferredTxFee
	rc.StakingRewardThreshold = new(big.Int).Set(paramset.StakingRewardThreshold)
	rc.UseFlexReward = paramset.UseFlexReward
```

**File:** kaiax/reward/impl/getter.go (L303-303)
```go
		minted           = new(big.Int).Set(config.MintingAmount)
```

**File:** kaiax/reward/impl/blockstate.go (L46-55)
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
