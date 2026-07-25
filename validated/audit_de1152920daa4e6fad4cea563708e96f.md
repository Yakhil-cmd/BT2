The code path is real and the ordering is confirmed. Let me lay out the exact evidence.

**Execution order** — `mBlockState` is always registered as `{mReward, mSystem, ...}`: [1](#0-0) [2](#0-1) 

`FinalizeState` iterates modules in registration order, sequentially: [3](#0-2) 

**Step 1 — `mReward.FinalizeState` runs first**, calling `state.AddBalance` for every deferred-reward recipient (proposer, stakers, Fund1/KIF, Fund2/KEF, Fund3/KPF): [4](#0-3) 

**Step 2 — `mSystem.FinalizeState` runs second**, calling `RebalanceTreasury` on the same live `stateDB`: [5](#0-4) 

**Step 3 — `fillZeroed` reads live balance** (not a snapshot from before the block): [6](#0-5) 

**Step 4 — `SetBalance(addr, 0)` wipes the entire live balance**, including any in-block additions: [7](#0-6) 

The `remainder` (and thus `result.Burnt`) is computed from `totalZeroedAmount`, which was inflated by in-block additions: [8](#0-7) 

---

### Title
KIP-103 `fillZeroed` reads post-reward live stateDB balance, silently burning in-block KAIA additions — (`blockchain/system/rebalance.go`)

### Summary

`RebalanceTreasury` (KIP-103 path) reads zeroed-address balances from the live `stateDB` **after** `mReward.FinalizeState` has already credited deferred block rewards. Any KAIA added to a zeroed address within the fork block — via deferred reward distribution or a user transfer — is included in `totalZeroedBalance`, passes the `ErrRebalanceNotEnoughBalance` guard with an inflated total, and is then permanently destroyed by `SetBalance(addr, 0)`.

### Finding Description

The `blockStateModules` slice is ordered `[mReward, mSystem]`. `FinalizeState` iterates them sequentially. `mReward.FinalizeState` calls `state.AddBalance` for every deferred-reward recipient. If any zeroed address is also a reward recipient (e.g., a fund address like KIF/KEF registered in AddressBook), its balance is increased before `mSystem.FinalizeState` invokes `RebalanceTreasury`.

Inside `RebalanceTreasury`, `fillZeroed` calls `state.GetBalance(ret)` on the same live `stateDB` object — there is no snapshot or pre-block balance capture. The inflated value is stored in `result.Before.Zeroed[ret]` and summed into `totalZeroedAmount`. The KIP-103 guard `if isKIP103 && totalZeroedAmount.Cmp(totalAllocatedAmount) < 0` then passes (or passes more easily). Execution then calls `state.SetBalance(addr, big.NewInt(0))` for every zeroed address, wiping the entire live balance. The in-block addition is destroyed without any authorization.

The same issue applies to user transfers: a transaction sending KAIA to a zeroed address executes during `ApplyTransaction` (before `FinalizeState`), so its effect is also captured by `fillZeroed`.

### Impact Explanation

- **Unauthorized burn**: KAIA credited to a zeroed address within the fork block (deferred reward share or user transfer) is permanently destroyed. The sender/reward system loses those funds with no recourse.
- **Overstated `result.Burnt`**: The memo and supply accounting record a higher burn than the pre-block treasury balance, corrupting supply tracking.
- **`ErrRebalanceNotEnoughBalance` bypass**: If the pre-block zeroed balance was marginally below `totalAllocatedAmount`, in-block additions could push `totalZeroedAmount` above the threshold, causing rebalance to proceed when it should have aborted.

### Likelihood Explanation

The most automatic trigger is the deferred-reward path: on Kaia Mainnet/Kairos (both use `reward.deferredtxfee = true`), every block distributes minting + fee rewards to fund addresses. If any fund address (KIF, KEF) is also a zeroed address in the KIP-103 contract, the reward credited by `mReward.FinalizeState` is silently burned by `mSystem.FinalizeState` in the same block. No attacker action is required — the block proposer's normal reward distribution triggers it. A user transfer to a zeroed address via public RPC is a second, deliberate trigger path.

### Recommendation

Capture zeroed-address balances **before** any `FinalizeState` module runs (e.g., in `InitializeState`, or by snapshotting balances at the start of `RebalanceTreasury` from the parent block's state root), rather than reading from the live post-reward stateDB. Alternatively, reorder modules so `mSystem` runs before `mReward`, though this changes reward semantics and requires careful analysis.

### Proof of Concept

1. Configure a chain with KIP-103 fork at block N. Register address `A` as both a zeroed address in the rebalance contract and as the KIF fund address in AddressBook.
2. Mine block N with at least one transaction (to generate deferred fees).
3. `mReward.FinalizeState` credits `A` with its fund share (e.g., 1000 KAIA).
4. `mSystem.FinalizeState` → `RebalanceTreasury` → `fillZeroed` reads `state.GetBalance(A)` = pre-block balance + 1000 KAIA.
5. `SetBalance(A, 0)` destroys the entire amount.
6. Assert: `result.Burnt` > pre-block balance of `A`; the 1000 KAIA reward is gone from total supply.

### Citations

**File:** node/cn/backend.go (L603-603)
```go
	mBlockState := []kaiax.BlockStateModule{mReward, mSystem, mValset}
```

**File:** kaiax/supply/impl/testutil_test.go (L200-200)
```go
		[]kaiax.BlockStateModule{mReward, mSystem},
```

**File:** blockchain/state_processor.go (L138-142)
```go
	for _, module := range p.blockStateModules {
		if err := module.FinalizeState(header, statedb, txs, receipts); err != nil {
			return nil, err
		}
	}
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

**File:** kaiax/system/impl/blockstate.go (L40-41)
```go
	if chainConfig.IsKIP160ForkBlock(header.Number) || chainConfig.IsKIP103ForkBlock(header.Number) {
		rebalanceResult, err := bcsystem.RebalanceTreasury(state, m.Chain, header)
```

**File:** blockchain/system/rebalance.go (L196-213)
```go
func (result *rebalanceResult) fillZeroed(contract RebalanceCaller, state *state.StateDB) error {
	numRetiredBigInt, err := contract.GetZeroedCount(nil)
	if err != nil {
		logger.Error("Failed to get ZeroedCount from TreasuryRebalance contract", "err", err)
		return err
	}

	for i := 0; i < int(numRetiredBigInt.Int64()); i++ {
		ret, err := contract.Zeroeds(nil, big.NewInt(int64(i)))
		if err != nil {
			logger.Error("Failed to get Zeroeds from TreasuryRebalance contract", "err", err)
			return err
		}
		result.Before.Zeroed[ret] = state.GetBalance(ret)
		result.After.Zeroed[ret] = state.GetBalance(ret) // will be set as zero if rebalance succeeds
	}
	return nil
}
```

**File:** blockchain/system/rebalance.go (L307-311)
```go
	// Execution 1) Clear all balances of zeroeds
	for addr := range result.Before.Zeroed {
		state.SetBalance(addr, big.NewInt(0))
		result.After.Zeroed[addr] = big.NewInt(0)
	}
```

**File:** blockchain/system/rebalance.go (L322-323)
```go
	remainder := new(big.Int).Sub(totalZeroedAmount, totalAllocatedAmount)
	result.Burnt.Add(result.Burnt, remainder)
```
