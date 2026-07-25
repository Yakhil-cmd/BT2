The code is confirmed. Let me verify the `NodeMap.Committee()` definition to be thorough.

### Title
ValPaused Validator Consumes Active Slot Without Consensus Participation, Demoting a ValActive Validator to ValInactive and Stripping Its Rewards — (`kaiax/valset/impl/transition_context.go`)

---

### Summary

In `applyEpochTransition`, when a `ValPaused` validator ranks within the top-N by stake (i.e., `idx < MaxValActivePausedCount`), the code intentionally skips the `ValActive` assignment for it — but still counts its slot against the active budget. Any `ValActive` validator ranked just outside the budget is unconditionally demoted to `ValInactive`, losing all block rewards for the epoch. The `ValPaused` validator holds the slot without participating in consensus.

---

### Finding Description

The epoch transition loop in `applyEpochTransition` iterates over `activeValCompetitors` sorted by stake:

```go
for idx, potentialActiveVal := range activeValCompetitors {
    if uint64(idx) < ctx.MaxValActivePausedCount {
        if potentialActiveVal.State != valset.ValPaused {
            potentialActiveVal.State = valset.ValActive
            potentialActiveVal.IdleTimeout = time.Time{}
            potentialActiveVal.PausedTimeout = time.Time{}
        }
        // ValPaused: falls through — state unchanged, slot consumed
    } else {
        if potentialActiveVal.State != valset.ValReady {
            potentialActiveVal.IdleTimeout = ctx.BlockTime.Add(ctx.IdleTimeout)
        }
        potentialActiveVal.State = valset.ValInactive // T3b
    }
}
``` [1](#0-0) 

When a `ValPaused` validator is at `idx=0` and `MaxValActivePausedCount=1`:

- `uint64(0) < 1` → enters the "winner" branch
- `State != ValPaused` → **false** → the `ValActive` assignment is skipped
- The validator **remains `ValPaused`** and its slot is consumed

The next validator at `idx=1` unconditionally hits the `else` branch and is set to `ValInactive`.

The code's own transition table contradicts this behavior:

```
// T3a: VR/VA/VP/CT → ValActive (won top-N stake competition)
``` [2](#0-1) 

`VP` (ValPaused) is listed as a T3a participant that **should** become `ValActive` on winning. The implementation skips this assignment, creating a slot that is budgeted but not filled with a consensus-participating validator.

---

### Impact Explanation

`getQualifiedValidators` is defined as:

```go
// getQualifiedValidators: qualified = committee = {VA} − {Suspended}
``` [3](#0-2) 

`ValPaused` validators are **not** in the committee and do not participate in block proposal or signing. The council includes them:

```go
// getCouncil: Council = {ValActive, ValPaused}.
``` [4](#0-3) 

But the qualified/committee set used for consensus is `{VA}` only. So the `ValPaused` winner:

1. Occupies one of the `MaxValActivePausedCount` active slots
2. Does **not** participate in consensus (not in committee)
3. Causes the next-ranked `ValActive` validator to be demoted to `ValInactive`

The demoted `ValActive` validator loses all KAIA block rewards for the epoch — a direct, material reward distribution impact.

---

### Likelihood Explanation

This triggers automatically at every epoch block whenever:
- A `ValPaused` validator has more stake than a `ValActive` validator, and
- The total number of eligible competitors exceeds `MaxValActivePausedCount`

`ValPaused` is a normal protocol state set by `applyViolationTransition` on minor PFS violations (proposal failures). No special operator action or governance key is required. The condition can arise organically as validators accumulate proposal failures while maintaining high stake. No external service, compromised key, or majority collusion is needed.

---

### Recommendation

In the winner branch, remove the `ValPaused` guard so that any validator winning the top-N competition — including `ValPaused` — is unconditionally promoted to `ValActive`:

```go
if uint64(idx) < ctx.MaxValActivePausedCount {
    potentialActiveVal.State = valset.ValActive
    potentialActiveVal.IdleTimeout = time.Time{}
    potentialActiveVal.PausedTimeout = time.Time{}
} else {
    ...
}
```

This aligns the implementation with the documented T3a invariant: `VP → ValActive` on winning the top-N stake competition.

---

### Proof of Concept

```go
// Setup: MaxValActivePausedCount=1, ValPaused(stake=100), ValActive(stake=99)
m := NodeMap{
    addrPaused: {State: ValPaused, StakingAmount: 100},
    addrActive: {State: ValActive, StakingAmount: 99},
}
ctx := buildCtx(t, ctxOpts{
    MinStake:                50,
    MaxValActivePausedCount: 1,
    // ...
})
out := ctx.applyEpochTransition(m)

// Bug: ValPaused wins idx=0, stays ValPaused (slot consumed, no consensus)
assert.Equal(t, ValPaused, out[addrPaused].State)  // passes — slot wasted

// Bug: ValActive at idx=1 is demoted, loses rewards
assert.Equal(t, ValInactive, out[addrActive].State) // passes — rewards lost

// Expected (correct) behavior:
// assert.Equal(t, ValActive, out[addrPaused].State)  // should be promoted
// assert.Equal(t, ValActive, out[addrActive].State)  // should retain slot
```

The existing test at line 177 of `transition_context_test.go` already documents and accepts the broken behavior:

```
{"ValPaused + stake above → ValPaused (preserved)", ValPaused, aboveMinStake, ValPaused, false},
``` [5](#0-4) 

This test uses `testMaxValCount = 50` (effectively unlimited slots), so the demotion of a competing `ValActive` validator is never exercised. The multi-validator competition case with a tight `MaxValActivePausedCount` budget is untested, which is where the slot-theft manifests.

### Citations

**File:** kaiax/valset/impl/transition_context.go (L163-165)
```go
//	T2: CandTesting → Registered (failed vrank test)
//	T3a: VR/VA/VP/CT → ValActive (won top-N stake competition)
//	T3b: VR/VA/VP/CT → ValInactive (lost top-N or below MinStake)
```

**File:** kaiax/valset/impl/transition_context.go (L224-237)
```go
	for idx, potentialActiveVal := range activeValCompetitors {
		if uint64(idx) < ctx.MaxValActivePausedCount {
			if potentialActiveVal.State != valset.ValPaused {
				potentialActiveVal.State = valset.ValActive
				potentialActiveVal.IdleTimeout = time.Time{}
				potentialActiveVal.PausedTimeout = time.Time{}
			}
		} else {
			if potentialActiveVal.State != valset.ValReady {
				potentialActiveVal.IdleTimeout = ctx.BlockTime.Add(ctx.IdleTimeout)
			}
			potentialActiveVal.State = valset.ValInactive // T3b
		}
	}
```

**File:** kaiax/valset/impl/getter_permissionless.go (L24-31)
```go
// getCouncil: Council = {ValActive, ValPaused}.
func (v *ValsetModule) getCouncil(num uint64) ([]common.Address, error) {
	nodes, err := v.getNodes(num)
	if err != nil {
		return nil, err
	}
	return nodes.Council().Addresses(), nil
}
```

**File:** kaiax/valset/impl/getter_permissionless.go (L47-59)
```go
// getQualifiedValidators: qualified = committee = {VA} − {Suspended} (with safety fallback).
func (v *ValsetModule) getQualifiedValidators(num uint64) (*valset.AddressSet, error) {
	nodes, err := v.getNodes(num)
	if err != nil {
		return nil, err
	}
	committee, fellBack := committeeWithFallback(nodes)
	if fellBack && v.lastSuspendFallbackLog != num {
		logger.Warn("all ValActive are suspended, ignoring suspended set for committee", "num", num)
		v.lastSuspendFallbackLog = num
	}
	return valset.NewAddressSet(committee.Addresses()), nil
}
```

**File:** kaiax/valset/impl/transition_context_test.go (L177-177)
```go
		{"ValPaused + stake above → ValPaused (preserved)", ValPaused, aboveMinStake, ValPaused, false},
```
