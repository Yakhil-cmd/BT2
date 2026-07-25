### Title
Unbounded `reward.mintingamount` Governance Parameter Allows Unlimited KAIA Minting Per Block — (`kaiax/gov/param.go`)

---

### Summary

The `reward.mintingamount` governance parameter is registered with `noopFormatChecker`, meaning any non-negative `*big.Int` value is accepted without an upper bound. A governing node (in `"single"` governance mode) can vote to set this parameter to an astronomically large value. Once the vote takes effect at the next epoch boundary, every block will mint that amount of KAIA and distribute it to validators and funds via `state.AddBalance()`, causing unauthorized and unbounded minting of KAIA tokens.

---

### Finding Description

In `kaiax/gov/param.go`, the `RewardMintingAmount` parameter is defined as:

```go
RewardMintingAmount: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: noopFormatChecker,   // always returns true — no upper bound
    ...
    DefaultValue: big.NewInt(0),
},
``` [1](#0-0) 

The `noopFormatChecker` unconditionally returns `true`:

```go
func noopFormatChecker(cv any) bool {
    return true
}
``` [2](#0-1) 

The `bigIntCanonicalizer` accepts any valid decimal string or `*big.Int` with no magnitude check: [3](#0-2) 

The `checkConsistency` function in `headergov` does not add any cross-parameter bound check for `RewardMintingAmount` — it falls through to the `return nil` branch: [4](#0-3) 

Once the vote is committed and the epoch boundary is reached, `NewRewardConfig` reads the unbounded value directly:

```go
rc.MintingAmount = new(big.Int).Set(paramset.MintingAmount)
``` [5](#0-4) 

`FinalizeState` then calls `state.AddBalance` with the full minting amount every block:

```go
for addr, amount := range spec.Rewards {
    state.AddBalance(addr, amount)
}
``` [6](#0-5) 

There is no cap, sanity check, or overflow guard anywhere in the reward calculation path for `MintingAmount`. [7](#0-6) 

---

### Impact Explanation

Setting `reward.mintingamount` to an astronomically large value (e.g., `new(big.Int).Exp(big.NewInt(2), big.NewInt(200), nil)`) causes every subsequent block to mint and distribute that amount of KAIA to validators and ecosystem funds. This is an **unauthorized minting** of KAIA — a direct asset impact. The corrupted value is written into the live state trie via `state.AddBalance` on every finalized block, permanently inflating balances of reward recipients and destroying the token supply invariant.

---

### Likelihood Explanation

In Kaia Mainnet's `"single"` governance mode, a single governing node address controls all governance votes. If that key is compromised or acts maliciously, it can cast a `reward.mintingamount` vote for any `*big.Int` value. The vote takes effect at the next epoch boundary (default epoch = 604,800 blocks). There is no on-chain guard that would reject or revert the minting at block finalization time. The attack path is:

1. Governing node submits a header vote for `reward.mintingamount = 2^200`
2. Vote is accepted (passes `noopFormatChecker`)
3. At the next epoch boundary, the governance data is committed to the chain
4. Every subsequent block mints `2^200` KAIA and distributes it to validators/funds

---

### Recommendation

Add a sensible upper bound to the `FormatChecker` for `RewardMintingAmount`, analogous to how `GovernanceDeriveShaImpl` is bounded to `v <= 2`. For example, cap the minting amount at a value consistent with the intended maximum annual inflation (e.g., `1e27` wei, roughly 1 billion KAIA):

```go
RewardMintingAmount: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(*big.Int)
        if !ok {
            return false
        }
        maxMint := new(big.Int).Exp(big.NewInt(10), big.NewInt(27), nil) // 1e27 wei
        return v.Sign() >= 0 && v.Cmp(maxMint) <= 0
    },
    ...
},
``` [1](#0-0) 

---

### Proof of Concept

**Precondition**: Kaia mainnet in `"single"` governance mode. Governing node key is compromised.

**Steps**:

1. Attacker controlling the governing node submits a header vote:
   ```
   Vote: ("reward.mintingamount", "1606938044258990275541962092341162602522202993782792835301376")
   // = 2^200
   ```
   This passes `NewVoteData` (canonicalized to `*big.Int`, `noopFormatChecker` returns `true`).

2. `VerifyVote` in `headergov` accepts the vote — `checkConsistency` returns `nil` for `RewardMintingAmount`. [4](#0-3) 

3. At the next epoch boundary, the governance data is written to the chain header.

4. For every subsequent block, `NewRewardConfig` reads `MintingAmount = 2^200`: [8](#0-7) 

5. `FinalizeState` calls `getDeferredReward`, which sets `minted = 2^200` and distributes it proportionally to validators and funds. [9](#0-8) 

6. `state.AddBalance(addr, 2^200)` is called for each reward recipient every block, permanently corrupting all recipient balances in the state trie.

**Corrupted value**: Validator and fund balances in the state trie are inflated by `2^200` KAIA per block, destroying the KAIA token supply invariant.

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

**File:** kaiax/gov/headergov/impl/header.go (L204-211)
```go
		// These votes are valid as long as it passes the format checks in NewVoteData(). No more checks here.
	case gov.GovernanceDeriveShaImpl, gov.GovernanceGovParamContract, gov.GovernanceGovernanceMode, gov.GovernanceUnitPrice,
		gov.IstanbulCommitteeSize, gov.IstanbulEpoch, gov.IstanbulPolicy,
		gov.Kip71BaseFeeDenominator, gov.Kip71GasTarget, gov.Kip71MaxBlockGasUsedForBaseFee,
		gov.RewardDeferredTxFee, gov.RewardKip82Ratio, gov.RewardMintingAmount, gov.RewardMinimumStake,
		gov.RewardProposerUpdateInterval, gov.RewardRatio, gov.RewardStakingRewardThreshold,
		gov.RewardStakingUpdateInterval, gov.RewardUseFlexReward, gov.RewardUseGiniCoeff:
		return nil
```

**File:** kaiax/reward/config.go (L59-62)
```go
	paramset := govModule.GetParamSet(header.Number.Uint64())
	rc.IsSimple = paramset.ProposerPolicy != uint64(istanbul.WeightedRandom)
	rc.UnitPrice = new(big.Int).SetUint64(paramset.UnitPrice)
	rc.MintingAmount = new(big.Int).Set(paramset.MintingAmount)
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

**File:** kaiax/reward/impl/getter.go (L227-227)
```go
	minted := new(big.Int).Set(config.MintingAmount)
```
