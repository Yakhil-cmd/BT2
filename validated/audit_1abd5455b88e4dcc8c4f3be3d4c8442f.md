### Title
Native KAIA Balance of Staking Contracts Used Directly as Reward-Weight Input Allows Inflation of Validator Staking Rewards — (`kaiax/staking/impl/getter.go`, `kaiax/reward/impl/getter.go`)

---

### Summary

The Kaia staking module derives each validator's staking weight for block-reward distribution directly from the **native KAIA balance** of the registered staking-contract addresses. Because any account can send KAIA to an arbitrary address (including via `selfdestruct` force-send), a validator can inflate its own staking-contract balance without going through the official stake/unstake flow, causing it to receive a disproportionately large share of the per-block staking rewards at the expense of all other validators.

---

### Finding Description

`kaiax/staking/README.md` explicitly documents the design:

> *StakingInfo summarizes the current AddressBook contract state, and all the staking contracts registered in the AddressBook, and their **native token balances**.* [1](#0-0) 

`GetStakingInfo` → `getFromStateByNumber` → `getFromState` calls the injected `MultiCallContract` which reads the native KAIA balance of every staking-contract address registered in the AddressBook and returns those values as `stakingAmounts`. [2](#0-1) 

The returned amounts are stored verbatim in `StakingInfo.StakingAmounts` (in KAIA, rounded down): [3](#0-2) 

The integration test confirms the 1-to-1 mapping: a staking contract whose genesis `Balance` is set to `42_000_000 KAIA` produces `StakingAmounts[0] == 42_000_000`: [4](#0-3) 

These amounts are then consumed by `assignStakingRewards` / `assignStakingRewardsFlex` to compute each validator's proportional share of the staking-reward budget: [5](#0-4) 

The reward is:

```
reward_i = (stakingAmount_i - minStake) / totalExcess * stakersReward
```

Because `stakingAmount_i` is the raw native balance, any KAIA deposited directly into the staking-contract address — outside the official staking flow — increases `stakingAmount_i` and therefore increases `reward_i`.

The computed `RewardSpec` is applied unconditionally in `FinalizeState`: [6](#0-5) 

---

### Impact Explanation

A validator (or any party acting on its behalf) sends KAIA directly to its own staking-contract address (e.g., via a plain transfer if the contract has a `receive()` fallback, or via `selfdestruct` force-send which bypasses all receive guards). At the next source-block snapshot the inflated balance is read as the staking amount. For every subsequent block that uses this snapshot the validator receives a larger fraction of the staking-reward budget, while every other validator receives a correspondingly smaller fraction. The total KAIA minted per block is unchanged; the redistribution is purely among validators. The corrupted value is `StakingInfo.StakingAmounts[i]` and, downstream, the per-address entries in `RewardSpec.Rewards`.

---

### Likelihood Explanation

- After the Kaia hardfork the source block is `num - 1`, so the inflated balance takes effect in the very next block — no epoch delay.
- `selfdestruct` force-send is always available regardless of the staking contract's receive logic.
- The attack is profitable whenever the present-value of the extra staking rewards exceeds the KAIA deposited (which remains locked in the staking contract but is not destroyed).
- No privileged role is required; any account can send KAIA to any address.

---

### Recommendation

Replace the raw native-balance read with a call to the staking contract's internal accounting function (e.g., `staking()` on `CnStakingV4`) so that only KAIA deposited through the official stake entry-point is counted. Alternatively, implement a before/after balance snapshot around the staking-info collection (analogous to the TREC-3 fix) and use only the delta attributable to legitimate stake operations. For the CLPool path the same principle applies to `CLStakingAmount`.

---

### Proof of Concept

1. Validator V has staking contract `S` with balance `5_000_001 KAIA` (just above `minStake = 5_000_000`). Two other validators have `5_000_002` and `5_000_003` KAIA respectively. V's share of staking rewards is `1 / (1+2+3) = 1/6`.

2. V deploys a helper contract `Bomb` holding `X KAIA` and calls `selfdestruct(S)`. The native balance of `S` becomes `5_000_001 + X`.

3. At block `num`, `GetStakingInfo(num-1)` reads `S.balance = 5_000_001 + X`. `assignStakingRewards` computes V's excess as `1 + X` instead of `1`, inflating V's share.

4. `FinalizeState` calls `state.AddBalance(V.rewardAddr, inflatedAmount)`, crediting V with more KAIA than the protocol intends, and reducing the amounts credited to the other two validators. [3](#0-2) [7](#0-6) [8](#0-7)

### Citations

**File:** kaiax/staking/README.md (L7-9)
```markdown
- StakingInfo is a struct representing Validator staking information at a certain block including staked amount, reward address, and node address. It is primarily used to determine validator set and rewards distribution.
- StakingInfo summarizes the current AddressBook contract state, and all the staking contracts registered in the AddressBook, and their native token balances.
  - Since the Prague hardfork, the StakingInfo will include the [consensus liquidity](https://kips.kaia.io/KIPs/kip-226) information from the CLRegistry.
```

**File:** kaiax/staking/impl/getter.go (L103-180)
```go
func (s *StakingModule) getFromState(header *types.Header, statedb *state.StateDB) (*staking.StakingInfo, error) {
	isForPrague := s.ChainConfig.IsPragueForkEnabled(new(big.Int).Add(header.Number, common.Big1))
	isForPermissionless := s.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).Add(header.Number, common.Big1))
	num := header.Number.Uint64()

	// Bail out if AddressBook is not installed.
	// This is a common case for private nets.
	if statedb.GetCode(system.AddressBookAddr) == nil {
		logger.Trace("AddressBook not installed", "sourceNum", num)
		return emptyStakingInfo(num), nil
	}

	// Now we're safe to call the MultiCall contract.
	contract, err := system.NewMultiCallContractCaller(statedb, s.Chain, header)
	if err != nil {
		return nil, staking.ErrMultiCallCall(err)
	}

	callOpts := &bind.CallOpts{BlockNumber: header.Number}

	// Helper to read CL registry info, shared by permissioned and permissionless paths.
	// Permissionless is ordered after Prague (Randao <= Kaia <= Prague <= Permissionless),
	// so permissionless blocks always need CL registry info too.
	readCLInfo := func() (clRegistryResult, error) {
		var clRes clRegistryResult
		// If Registry is not installed, do not handle CL staking info.
		// In private network, Randao and Prague hardfork can be activated at the same block.
		// It leads to staking info inconsistency between block processing and rpc query since the Registry hasn't been installed when finalizing the header.
		// Note that Randao can't be activated after Prague according to fork ordering (Randao <= Kaia <= Prague).
		if statedb.GetCode(system.RegistryAddr) == nil || s.ChainConfig.IsRandaoForkBlockParent(header.Number) {
			logger.Trace("Registry not installed", "sourceNum", num)
			return clRes, nil
		}
		// Note that if CLRegistry is not registered in Registry,
		// it will return empty result and no error.
		clRes, err = contract.MultiCallDPStakingInfo(callOpts)
		if err != nil {
			return clRes, staking.ErrCLRegistryCall(err)
		}
		return clRes, nil
	}

	// Permissionless: read from AddressBookV2 (effective stake, reward-eligible only).
	if isForPermissionless {
		res, err := contract.MultiCallStakingInfoPermissionless(callOpts)
		if err != nil {
			return nil, staking.ErrAddressBookCall(err)
		}
		clRes, err := readCLInfo()
		if err != nil {
			return nil, err
		}
		return parsePermissionlessCallResult(num, res.Profiles, res.StakingAmounts, res.KefAddr, res.KifAddr, res.KpfAddr, clRes)
	}

	// Permissioned: read from legacy AddressBook.
	abRes, err := contract.MultiCallStakingInfo(callOpts)
	if err != nil {
		return nil, staking.ErrAddressBookCall(err)
	}

	var clRes clRegistryResult
	if isForPrague {
		clRes, err = readCLInfo()
		if err != nil {
			return nil, err
		}
	}

	return parseCallResult(
		num,
		abRes.TypeList,
		abRes.AddressList,
		abRes.StakingAmounts,
		clRes,
		abRes.SpareAddress,
	)
}
```

**File:** kaiax/staking/impl/getter.go (L286-288)
```go
	for i, a := range amounts {
		stakingAmounts[i] = big.NewInt(0).Div(a, big.NewInt(params.KAIA)).Uint64()
	}
```

**File:** kaiax/staking/impl/getter_test.go (L83-112)
```go
			common.HexToAddress("0x0000000000000000000000000000000000000F01"): { // staking1
				Balance: new(big.Int).Mul(big.NewInt(42_000_000), big.NewInt(params.KAIA)),
			},
			common.HexToAddress("0x0000000000000000000000000000000000000f04"): { // staking2
				Balance: new(big.Int).Mul(big.NewInt(99_000_000), big.NewInt(params.KAIA)),
			},
		}
		config = testPragueForkChainConfig(nil)

		// Addresses are already stored in AddressBookMock.sol:AddressBookMockTwoCN
		// The balances are given at the GenesisAlloc above
		expected = &staking.StakingInfo{
			SourceBlockNum: 0,
			NodeIds: []common.Address{
				common.HexToAddress("0x0000000000000000000000000000000000000F00"),
				common.HexToAddress("0x0000000000000000000000000000000000000F03"),
			},
			StakingContracts: []common.Address{
				common.HexToAddress("0x0000000000000000000000000000000000000F01"),
				common.HexToAddress("0x0000000000000000000000000000000000000f04"),
			},
			RewardAddrs: []common.Address{
				common.HexToAddress("0x0000000000000000000000000000000000000f02"),
				common.HexToAddress("0x0000000000000000000000000000000000000f05"),
			},
			KIFAddr:        common.HexToAddress("0x0000000000000000000000000000000000000F06"),
			KEFAddr:        common.HexToAddress("0x0000000000000000000000000000000000000f07"),
			StakingAmounts: []uint64{42_000_000, 99_000_000},
			CLStakingInfos: nil,
		}
```

**File:** kaiax/reward/impl/getter.go (L488-534)
```go
func assignStakingRewards(config *reward.RewardConfig, stakersReward *big.Int, si *staking.StakingInfo) (map[common.Address]*big.Int, *big.Int) {
	var (
		cns               = si.ConsolidatedNodes()
		minStake          = config.MinimumStake.Uint64()
		totalExcessInt    = uint64(0) // sum of excess stakes (the amount over minStake) over all stakers
		cnTotalStakingMap = make(map[common.Address]uint64)
		isPrague          = config.Rules.IsPrague
	)
	for _, cn := range cns {
		// If the CNStaking is less than minStake, skip it.
		if cn.StakingAmount >= minStake {
			// Calculate total staking amount once
			cnTotalStakingAmount := cn.StakingAmount
			if isPrague && cn.CLStakingInfo != nil {
				cnTotalStakingAmount += cn.CLStakingInfo.CLStakingAmount
			}
			totalExcessInt += cnTotalStakingAmount - minStake
			cnTotalStakingMap[cn.RewardAddr] = cnTotalStakingAmount
		}
	}

	var (
		totalExcess = new(big.Int).SetUint64(totalExcessInt)
		remaining   = new(big.Int).Set(stakersReward)
		alloc       = make(map[common.Address]*big.Int)
	)
	for _, cn := range cns {
		cnTotalStakingAmount := cnTotalStakingMap[cn.RewardAddr]
		if cnTotalStakingAmount > minStake {
			// The KAIA unit will cancel out:
			// reward (kei) = excess (KAIA) * stakersReward (kei) / totalExcess (KAIA)
			excess := new(big.Int).SetUint64(cnTotalStakingAmount - minStake)
			if reward := new(big.Int).Div(new(big.Int).Mul(excess, stakersReward), totalExcess); reward.Sign() > 0 {
				if isPrague && cn.CLStakingInfo != nil {
					// The remaining amount will be added to the cnAmount.
					cnAmount, clAmount := cn.Split(reward)
					alloc[cn.RewardAddr] = cnAmount
					alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
				} else {
					alloc[cn.RewardAddr] = reward
				}
				remaining.Sub(remaining, reward)
			}
		}
	}
	return alloc, remaining
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
