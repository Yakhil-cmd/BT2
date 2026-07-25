### Title
Zero Reward Address in Staking Info Causes Permanent KAIA Burn in Block Reward Distribution — (`kaiax/reward/impl/blockstate.go`, `kaiax/staking/impl/getter.go`, `kaiax/reward/spec.go`)

---

### Summary

When a validator's reward address in the AddressBook is `address(0)`, the staking reward distribution pipeline has no guard to intercept it. `FinalizeState` calls `state.AddBalance(address(0), amount)` for every entry in `spec.Rewards`, silently crediting KAIA to the zero address — permanently burning those tokens. Neither the staking-info parsing layer nor the reward-spec validation layer checks for zero recipient addresses.

---

### Finding Description

**Step 1 — Staking info parsing admits zero reward addresses.**

`parseCallResult` in `kaiax/staking/impl/getter.go` performs a sanity check on the AddressBook result, but it only guards the two fund addresses (`kefAddr`, `kifAddr`) against being empty. Individual validator `rewardAddrs` entries are accepted verbatim with no zero-address filter:

```go
// Sanity check
// Note that kpfAddr (spareAddr) can be empty even after the AddressBook is activated.
if len(nodeIds) != len(stakingContracts) || len(nodeIds) != len(rewardAddrs) || len(nodeIds) != len(amounts) ||
    common.EmptyAddress(kefAddr) || common.EmptyAddress(kifAddr) {
    ...
    return emptyStakingInfo(num), nil
}
``` [1](#0-0) 

The same omission exists in `parsePermissionlessCallResult`, which appends `p.RewardAddress` directly without any zero-check:

```go
rewardAddrs = append(rewardAddrs, p.RewardAddress)
``` [2](#0-1) 

**Step 2 — Reward allocation writes to `address(0)` without guard.**

`assignStakingRewards` and `assignStakingRewardsFlex` both key their allocation maps on `cn.RewardAddr`. If that field is `address(0)`, the reward is placed under the zero key:

```go
alloc[cn.RewardAddr] = reward
``` [3](#0-2) 

```go
alloc[cn.RewardAddr] = cnAmount
alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
``` [4](#0-3) 

**Step 3 — `spec.Validate()` does not check for zero-address recipients.**

The only validation performed is a sign check on amounts:

```go
func (spec *RewardSpec) Validate() error {
    for addr, amount := range spec.Rewards {
        if amount.Sign() < 0 {
            return errNegativeRewardAmount(addr, amount)
        }
    }
    return nil
}
``` [5](#0-4) 

A zero-address recipient with a positive amount passes validation silently.

**Step 4 — `FinalizeState` calls `AddBalance` on every recipient, including `address(0)`.**

```go
for addr, amount := range spec.Rewards {
    state.AddBalance(addr, amount)
}
``` [6](#0-5) 

Unlike Solidity's ERC-20 `transfer`, Go's EVM `AddBalance` does not revert on `address(0)`. It silently credits the zero address, permanently burning those KAIA tokens — no revert, no error, no log.

**Amplification via `consolidateNodes()`.**

`consolidateNodes()` uses `RewardAddr` as a map key. If multiple validators share `address(0)` as their reward address, their staking amounts are summed into a single consolidated node, and the entire combined reward is burned in one call:

```go
cmap[r] = &consolidatedNode{
    ...
    RewardAddr:    r,
    StakingAmount: si.StakingAmounts[i],
}
``` [7](#0-6) 

---

### Impact Explanation

Every block in which a validator with a zero reward address is eligible for staking rewards results in a permanent, irreversible burn of KAIA tokens. The tokens are not locked in a contract — they are credited to `address(0)` in the EVM state, from which they can never be recovered. This constitutes an unauthorized burn of KAIA from the reward distribution pool, matching the allowed impact gate: *unauthorized burn affecting KAIA*.

---

### Likelihood Explanation

The trigger requires a validator's `RewardAddr` to be `address(0)` in the AddressBook state. The `reviseRewardAddress` function in the AddressBook mock (which mirrors the production interface) accepts any address including zero with no guard:

```solidity
function reviseRewardAddress(address _rewardAddress) external {
    ...
    cnRewardAddressList[index] = _rewardAddress;
    emit ReviseRewardAddress(...);
}
``` [8](#0-7) 

The production AddressBook contract source is not present in this repository, so it is unknown whether it enforces a non-zero check at the contract level. However, the Go-side parsing and reward distribution code has **no guard at any layer**, meaning any zero address that reaches the staking info — whether from a contract bug, a deliberate validator action, or a future contract upgrade — will silently burn rewards every block until corrected.

---

### Recommendation

1. **In `parseCallResult` and `parsePermissionlessCallResult`** (`kaiax/staking/impl/getter.go`): add a per-entry zero-address filter for `rewardAddrs`. Entries with `address(0)` as reward address should be skipped or cause the entire staking info to be treated as empty (consistent with the existing fund-address guard).

2. **In `spec.Validate()`** (`kaiax/reward/spec.go`): add a check that rejects any recipient address equal to `address(0)`:
   ```go
   if addr == (common.Address{}) {
       return errZeroAddressRecipient(amount)
   }
   ```

3. **In `assignStakingRewards` / `assignStakingRewardsFlex`** (`kaiax/reward/impl/getter.go`): skip any `cn` whose `RewardAddr` is `address(0)` and redirect the remainder to the proposer (consistent with the existing remainder-to-proposer policy).

---

### Proof of Concept

1. Validator's staking contract calls `reviseRewardAddress(address(0))` on the AddressBook.
2. At the next staking-info snapshot block, `GetStakingInfo` reads the AddressBook via `MultiCallStakingInfo`. `parseCallResult` includes the entry because only `kefAddr`/`kifAddr` are checked for zero — not individual `rewardAddrs`.
3. `StakingInfo.RewardAddrs[i] = address(0)` is stored and cached.
4. At block finalization, `FinalizeState` calls `GetDeferredReward` → `getDeferredRewardFull` → `assignStakingRewards`. The validator's proportional staking reward is placed in `alloc[address(0)]`.
5. `spec.Validate()` passes (amount is positive, no zero-address check).
6. `state.AddBalance(address(0), reward)` executes without error, permanently burning the validator's staking reward every block until the reward address is corrected.

### Citations

**File:** kaiax/staking/impl/getter.go (L207-207)
```go
		rewardAddrs = append(rewardAddrs, p.RewardAddress)
```

**File:** kaiax/staking/impl/getter.go (L304-311)
```go
	// Sanity check
	// Note that kpfAddr (spareAddr) can be empty even after the AddressBook is activated.
	if len(nodeIds) != len(stakingContracts) || len(nodeIds) != len(rewardAddrs) || len(nodeIds) != len(amounts) ||
		common.EmptyAddress(kefAddr) || common.EmptyAddress(kifAddr) {
		// This is an expected behavior when the AddressBook contract is not activated yet.
		logger.Trace("returning empty staking info because AddressBook is not activated", "sourceNum", num)
		return emptyStakingInfo(num), nil
	}
```

**File:** kaiax/reward/impl/getter.go (L476-477)
```go
			alloc[cn.RewardAddr] = cnAmount
			alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
```

**File:** kaiax/reward/impl/getter.go (L527-527)
```go
					alloc[cn.RewardAddr] = reward
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

**File:** kaiax/reward/impl/blockstate.go (L53-55)
```go
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
```

**File:** kaiax/staking/staking_info.go (L140-145)
```go
			cmap[r] = &consolidatedNode{
				NodeIds:          []common.Address{n},
				StakingContracts: []common.Address{si.StakingContracts[i]},
				RewardAddr:       r,
				StakingAmount:    si.StakingAmounts[i],
			}
```

**File:** contracts/testing/reward/AddressBookMock.sol (L258-273)
```text
    function reviseRewardAddress(address _rewardAddress) external {
        bool foundIt = false;
        uint256 index = 0;
        uint256 cnStakingContractListCnt = cnStakingContractList.length;
        for (uint256 i = 0; i < cnStakingContractListCnt; i++) {
            if (cnStakingContractList[i] == msg.sender) {
                foundIt = true;
                index = i;
                break;
            }
        }

        address prevAddress = cnRewardAddressList[index];
        cnRewardAddressList[index] = _rewardAddress;
        emit ReviseRewardAddress(cnNodeIdList[index], prevAddress, cnRewardAddressList[index]);
    }
```
