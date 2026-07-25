### Title
Cross-Parameter Governance Vote Allows `LowerBoundBaseFee > UpperBoundBaseFee`, Breaking Base-Fee Invariant — (`kaiax/gov/headergov/impl/header.go`)

---

### Summary

The `checkConsistency` function in the header-governance module validates each KIP-71 base-fee bound vote **only against the current value of the other bound**, not against any pending vote for that other bound in the same epoch. Two individually valid votes cast in the same epoch can therefore be ratified together to produce `LowerBoundBaseFee > UpperBoundBaseFee`. Once that state is active, `NextMagmaBlockBaseFee` can compute and accept a base fee that exceeds the governance-intended upper bound, causing every user in subsequent blocks to be charged more than the maximum fee the governance system is supposed to enforce.

---

### Finding Description

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` performs the following per-vote checks:

```go
case gov.Kip71LowerBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) > params.UpperBoundBaseFee {
        return ErrLowerBoundBaseFee
    }
case gov.Kip71UpperBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) < params.LowerBoundBaseFee {
        return ErrUpperBoundBaseFee
    }
``` [1](#0-0) 

Each vote is validated against `h.GetParamSet(blockNum)`, which returns the **currently active** parameter set, not the set that will be active after all pending votes in the same epoch are ratified.

The individual `FormatChecker` entries for both parameters are `noopFormatChecker`, meaning any `uint64` value is accepted without range restriction: [2](#0-1) 

There is no cross-parameter validation at ratification time. `VerifyGov` only checks that the ratified governance data matches the locally computed expected data (last vote per parameter), not that the combined parameter set is internally consistent: [3](#0-2) 

**Attack path (single-mode governance, governing node as semi-trusted actor):**

Assume current state: `LowerBoundBaseFee = 25e9`, `UpperBoundBaseFee = 750e9`.

1. Governing node casts vote: `LowerBoundBaseFee = 600e9`.  
   Check: `600e9 > 750e9`? No → vote accepted.
2. Governing node casts vote: `UpperBoundBaseFee = 400e9`.  
   Check: `400e9 < 25e9`? No → vote accepted.
3. At epoch boundary both votes are ratified: `LowerBoundBaseFee = 600e9`, `UpperBoundBaseFee = 400e9`.

Now `LowerBoundBaseFee > UpperBoundBaseFee`.

In `NextMagmaBlockBaseFee` (`params/kip71_config.go`), when gas usage is below target and the parent base fee has been clamped to `upperBoundBaseFee` (400e9), the computed `nextBaseFee` can fall below `lowerBoundBaseFee` (600e9), triggering the floor clamp:

```go
nextBaseFee := x.Sub(parentBaseFee, baseFeeDelta)
if nextBaseFee.Cmp(lowerBoundBaseFee) < 0 {
    return makeEvenByFloor(lowerBoundBaseFee)  // returns 600e9 > upperBound 400e9
}
``` [4](#0-3) 

`VerifyMagmaHeader` then computes the same expected value (600e9) and accepts the block, so the chain continues with a base fee permanently above the governance-intended upper bound. [5](#0-4) 

---

### Impact Explanation

Every transaction included in blocks after the invalid parameter combination takes effect pays a base fee that exceeds `UpperBoundBaseFee`. The base fee is burned (not redistributed), so users are charged more than the governance system is supposed to allow. This is an unauthorized fee charge affecting all KAIA users on the network for as long as the invalid parameter combination remains active. The invariant `LowerBoundBaseFee ≤ baseFee ≤ UpperBoundBaseFee` is broken at the consensus level.

---

### Likelihood Explanation

In `single` governance mode (Mainnet and Kairos), the governing node must cast both conflicting votes in the same epoch. This is a semi-trusted actor; the system is supposed to prevent them from creating invalid states even accidentally. In `none` mode, any GC member can cast both votes. The window is one full epoch (604,800 blocks on Mainnet), giving ample time for both votes to be included. No external attacker capability is required beyond the governing node's normal vote-casting privilege.

---

### Recommendation

Add a cross-parameter consistency check at **ratification time** (inside `getExpectedGovernance` or `VerifyGov`) that rejects any ratified parameter set where `LowerBoundBaseFee > UpperBoundBaseFee`. Additionally, update `checkConsistency` to also validate the new vote against any **already-pending vote** for the other bound in the current epoch, not just the currently active value:

```go
case gov.Kip71LowerBoundBaseFee:
    params := h.GetParamSet(blockNum)
    effectiveUpper := params.UpperBoundBaseFee
    // also check against any pending UpperBoundBaseFee vote in this epoch
    if vote.Value().(uint64) > effectiveUpper {
        return ErrLowerBoundBaseFee
    }
```

A simpler mitigation is to add a post-ratification validation step that checks `LowerBoundBaseFee <= UpperBoundBaseFee` before writing the governance data to the block header.

---

### Proof of Concept

1. Start a Kaia node in `single` governance mode with default KIP-71 parameters (`Lower=25e9`, `Upper=750e9`).
2. Call `governance_vote("kip71.lowerboundbasefee", 600000000000)` — passes `checkConsistency` (600e9 < 750e9).
3. Call `governance_vote("kip71.upperboundbasefee", 400000000000)` — passes `checkConsistency` (400e9 > 25e9).
4. Wait for the epoch boundary. Both votes are ratified: `Lower=600e9`, `Upper=400e9`.
5. Observe that `NextMagmaBlockBaseFee` returns 600e9 (the lower bound) when gas usage is below target, which exceeds the supposed upper bound of 400e9.
6. All subsequent blocks have `baseFee = 600e9`, and `VerifyMagmaHeader` accepts them, confirming the invariant is broken.

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L112-154)
```go
// VerifyGov checks the following:
// (1) governance must be empty in non-epoch block,
// (2) if there are no votes in the previous epoch, governance must be empty,
// (3) if any vote exists in the previous epoch, governance must not be empty,
// (4) the json must not contain unknown fields,
// (5) the parsed json must exactly match the map derived locally from the previous epoch's votes.
func (h *headerGovModule) VerifyGov(header *types.Header) error {
	// (1)
	if header.Number.Uint64()%h.epoch != 0 {
		if len(header.Governance) > 0 {
			logger.Error("governance is not allowed in non-epoch block", "num", header.Number.Uint64())
			return ErrGovInNonEpochBlock
		} else {
			return nil
		}
	}

	// (2), (3)
	expected := h.getExpectedGovernance(header.Number.Uint64())
	if len(header.Governance) == 0 {
		if len(expected.Items()) != 0 {
			return ErrGovVerification
		}

		return nil
	}

	// (4)
	var gb headergov.GovBytes = header.Governance
	actual, err := gb.ToGovData()
	if err != nil {
		logger.Error("DeserializeHeaderGov error", "num", header.Number.Uint64(), "governance", gb, "err", err)
		return err
	}

	// (5)
	if !reflect.DeepEqual(expected, actual) {
		logger.Error("Governance mismatch", "expected", expected, "actual", actual)
		return ErrGovVerification
	}

	return nil
}
```

**File:** kaiax/gov/headergov/impl/header.go (L179-192)
```go
	case gov.Kip71LowerBoundBaseFee:
		params := h.GetParamSet(blockNum)
		if vote.Value().(uint64) > params.UpperBoundBaseFee {
			return ErrLowerBoundBaseFee
		} else {
			return nil
		}
	case gov.Kip71UpperBoundBaseFee:
		params := h.GetParamSet(blockNum)
		if vote.Value().(uint64) < params.LowerBoundBaseFee {
			return ErrUpperBoundBaseFee
		} else {
			return nil
		}
```

**File:** kaiax/gov/param.go (L335-366)
```go
	Kip71LowerBoundBaseFee: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: noopFormatChecker,
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil || c.Governance.KIP71 == nil {
				return nil, errors.New("kip71 is not set")
			}
			return c.Governance.KIP71.LowerBoundBaseFee, nil
		},
		DefaultValue: uint64(25000000000),
	},
	Kip71MaxBlockGasUsedForBaseFee: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: noopFormatChecker,
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil || c.Governance.KIP71 == nil {
				return nil, errors.New("kip71 is not set")
			}
			return c.Governance.KIP71.MaxBlockGasUsedForBaseFee, nil
		},
		DefaultValue: uint64(60000000),
	},
	Kip71UpperBoundBaseFee: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: noopFormatChecker,
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil || c.Governance.KIP71 == nil {
				return nil, errors.New("kip71 is not set")
			}
			return c.Governance.KIP71.UpperBoundBaseFee, nil
		},
		DefaultValue: uint64(750000000000),
```

**File:** params/kip71_config.go (L45-56)
```go
func (kc *KIP71Config) VerifyMagmaHeader(headerBaseFee *big.Int, parentHeaderNumber *big.Int, parentHeaderBaseFee *big.Int, parentHeaderGasUsed uint64) error {
	if headerBaseFee == nil {
		return fmt.Errorf("header is missing baseFee")
	}
	// Verify the baseFee is correct based on the parent header.
	expectedBaseFee := kc.NextMagmaBlockBaseFee(parentHeaderNumber, parentHeaderBaseFee, parentHeaderGasUsed)
	if headerBaseFee.Cmp(expectedBaseFee) != 0 {
		return fmt.Errorf("invalid baseFee: have %s, want %s, parentBaseFee %s, parentGasUsed %d",
			headerBaseFee, expectedBaseFee, parentHeaderBaseFee, parentHeaderGasUsed)
	}
	return nil
}
```

**File:** params/kip71_config.go (L118-128)
```go
		gasUsedDelta := new(big.Int).SetUint64(gasTarget - parentGasUsed)
		x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
		y := x.Div(x, new(big.Int).SetUint64(gasTarget))
		baseFeeDelta := x.Div(y, baseFeeDenominator)

		nextBaseFee := x.Sub(parentBaseFee, baseFeeDelta)
		if nextBaseFee.Cmp(lowerBoundBaseFee) < 0 {
			return makeEvenByFloor(lowerBoundBaseFee)
		}
		return makeEvenByFloor(nextBaseFee)
	}
```
