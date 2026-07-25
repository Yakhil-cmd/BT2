### Title
Independent Per-Vote Bound Validation Allows `LowerBoundBaseFee > UpperBoundBaseFee` After Epoch Ratification — (`File: kaiax/gov/headergov/impl/header.go`)

---

### Summary

`checkConsistency` validates each KIP-71 base-fee bound vote only against the **current** (pre-epoch) parameter set, never against the other bound that may be pending in the same epoch. In `none` governance mode, two GC members can cast individually-valid votes in the same epoch that together produce `LowerBoundBaseFee > UpperBoundBaseFee` after ratification. `NextMagmaBlockBaseFee` consumes these bounds without any cross-validation, permanently corrupting the EIP-1559-style base fee calculation for every subsequent block.

---

### Finding Description

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` handles the two KIP-71 bound parameters as follows:

```go
case gov.Kip71LowerBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) > params.UpperBoundBaseFee {   // only checks against CURRENT upper
        return ErrLowerBoundBaseFee
    } else {
        return nil
    }
case gov.Kip71UpperBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) < params.LowerBoundBaseFee {   // only checks against CURRENT lower
        return ErrUpperBoundBaseFee
    } else {
        return nil
    }
``` [1](#0-0) 

Each check is performed against `h.GetParamSet(blockNum)`, which returns the **currently ratified** parameter set, not the set of votes pending in the same epoch. Because votes are collected across an entire epoch and only the last vote per parameter wins at epoch end, two votes cast in the same epoch are never cross-validated against each other.

In `none` governance mode (the default for new chains, per `DefaultGovernanceMode = "none"`), any GC member may cast a vote for any parameter. Two GC members can therefore submit:

1. `kip71.lowerboundbasefee = 500 Gkei` — passes: `500 < 750` (current upper)
2. `kip71.upperboundbasefee = 100 Gkei` — passes: `100 > 25` (current lower)

At the epoch boundary, `VerifyGov` only checks that `header.Governance` matches the locally-derived vote map; it performs no cross-parameter consistency check on the resulting values. [2](#0-1) 

After ratification, the effective parameter set contains `LowerBoundBaseFee = 500 Gkei` and `UpperBoundBaseFee = 100 Gkei`.

---

### Impact Explanation

`NextMagmaBlockBaseFee` in `params/kip71_config.go` consumes these bounds without validating their relative order:

```go
lowerBoundBaseFee := new(big.Int).SetUint64(kc.LowerBoundBaseFee)
upperBoundBaseFee := new(big.Int).SetUint64(kc.UpperBoundBaseFee)
...
if parentBaseFee.Cmp(upperBoundBaseFee) >= 0 {
    parentBaseFee = upperBoundBaseFee   // fires for any fee ≥ 100 Gkei
} else if parentBaseFee.Cmp(lowerBoundBaseFee) <= 0 {
    parentBaseFee = lowerBoundBaseFee   // dead branch: never reached
}
``` [3](#0-2) 

With `lower=500 > upper=100`, the first branch fires for any `parentBaseFee ≥ 100 Gkei`, pinning `parentBaseFee` to 100 Gkei (the inverted upper). The second branch is unreachable. All subsequent fee calculations are then bounded by the wrong value. `VerifyMagmaHeader` enforces that every block's `baseFee` equals `NextMagmaBlockBaseFee`, so all honest nodes accept the same corrupted fee — the base fee mechanism is permanently broken for the chain. [4](#0-3) 

This is a **protected governance state corruption**: the KIP-71 base fee bounds are chain-level parameters that govern transaction fee collection for every block. Corrupting them to an inverted state permanently breaks the EIP-1559 fee adjustment mechanism, causing all transaction fees to be computed against an incorrect floor.

---

### Likelihood Explanation

In `none` governance mode (the default for new Kaia chains), any two GC members can independently cast the two conflicting votes in the same epoch. No coordination beyond timing is required — each vote passes its individual consistency check. The attack requires no special privilege beyond being a GC member (validator), which is a semi-trusted role. In `single` mode (Mainnet/Kairos), only the governing node can trigger this, which is a privileged operation.

---

### Recommendation

Cross-validate both bounds at the epoch boundary in `VerifyGov` (or when applying governance), ensuring the resulting `LowerBoundBaseFee ≤ UpperBoundBaseFee` after all votes in the epoch are merged. Alternatively, in `checkConsistency`, also check the new lower bound against any pending `UpperBoundBaseFee` vote in the same epoch (and vice versa).

A minimal fix for `checkConsistency`:

```go
case gov.Kip71LowerBoundBaseFee:
    params := h.GetParamSet(blockNum)
    newLower := vote.Value().(uint64)
    // Also check against any pending upper bound vote in this epoch
    pendingUpper := getPendingVoteValue(epochIdx, gov.Kip71UpperBoundBaseFee, params.UpperBoundBaseFee)
    if newLower > pendingUpper {
        return ErrLowerBoundBaseFee
    }
```

Or add a post-ratification cross-check in `VerifyGov`:

```go
if newLower, ok := govData[gov.Kip71LowerBoundBaseFee]; ok {
    if newUpper, ok2 := govData[gov.Kip71UpperBoundBaseFee]; ok2 {
        if newLower.(uint64) > newUpper.(uint64) {
            return ErrBoundInversion
        }
    }
}
```

---

### Proof of Concept

**Setup**: A Kaia chain in `none` governance mode with default KIP-71 params (`lower=25 Gkei`, `upper=750 Gkei`), epoch=604800.

**Steps**:

1. GC member A calls `governance_vote("kip71.lowerboundbasefee", 500000000000)` (500 Gkei).
   - `checkConsistency`: `500 Gkei < 750 Gkei` (current upper) → **passes**.
   - Vote is inscribed in `header.Vote` when A proposes a block.

2. GC member B calls `governance_vote("kip71.upperboundbasefee", 100000000000)` (100 Gkei) in the **same epoch**.
   - `checkConsistency`: `100 Gkei > 25 Gkei` (current lower) → **passes**.
   - Vote is inscribed in `header.Vote` when B proposes a block.

3. At the epoch boundary block, `getExpectedGovernance` collects both votes. `VerifyGov` confirms the governance field matches — no cross-bound check is performed.

4. Starting from `(k+1)*epoch`, `GetParamSet` returns `LowerBoundBaseFee=500 Gkei`, `UpperBoundBaseFee=100 Gkei`.

5. `NextMagmaBlockBaseFee` is called for every subsequent block. With any `parentBaseFee ≥ 100 Gkei`, the clamping at line 82 sets `parentBaseFee = 100 Gkei` (the inverted upper). The lower-bound clamp at line 84 is never reached. The base fee is permanently pinned to 100 Gkei regardless of network gas usage, breaking the KIP-71 fee adjustment mechanism. [1](#0-0) [5](#0-4)

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L118-153)
```go
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

**File:** params/kip71_config.go (L58-86)
```go
func (kc *KIP71Config) NextMagmaBlockBaseFee(parentHeaderNumber *big.Int, parentHeaderBaseFee *big.Int, parentHeaderGasUsed uint64) *big.Int {
	// governance parameters
	lowerBoundBaseFee := new(big.Int).SetUint64(kc.LowerBoundBaseFee)
	upperBoundBaseFee := new(big.Int).SetUint64(kc.UpperBoundBaseFee)
	makeEvenByCeil(lowerBoundBaseFee)
	makeEvenByFloor(upperBoundBaseFee)

	// If the parent is the magma disabled block or genesis, then return the lowerBoundBaseFee (default 25ston)
	if parentHeaderNumber.Cmp(new(big.Int).SetUint64(0)) == 0 || parentHeaderBaseFee == nil {
		return makeEvenByFloor(lowerBoundBaseFee)
	}

	var baseFeeDenominator *big.Int
	if kc.BaseFeeDenominator == 0 {
		// To avoid panic, set the fluctuation range small
		baseFeeDenominator = new(big.Int).SetUint64(64)
	} else {
		baseFeeDenominator = new(big.Int).SetUint64(kc.BaseFeeDenominator)
	}
	gasTarget := kc.GasTarget
	upperGasLimit := kc.MaxBlockGasUsedForBaseFee

	// check the case of upper/lowerBoundBaseFee is updated by governance mechanism
	parentBaseFee := parentHeaderBaseFee
	if parentBaseFee.Cmp(upperBoundBaseFee) >= 0 {
		parentBaseFee = upperBoundBaseFee
	} else if parentBaseFee.Cmp(lowerBoundBaseFee) <= 0 {
		parentBaseFee = lowerBoundBaseFee
	}
```
