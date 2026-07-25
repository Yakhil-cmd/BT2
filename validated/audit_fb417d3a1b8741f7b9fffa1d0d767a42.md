### Title
Single-Step Ownership Transfer in `GovParam` Permanently Bricks On-Chain Governance Parameter Updates — (`contracts/bindings/gov/GovParam.go` / `contracts/libs/openzeppelin-contracts-v2/contracts/ownership/Ownable.sol`)

---

### Summary

The `GovParam` system contract — which is the sole authoritative source for all on-chain governance parameters (KAIA minting amount, reward ratios, unit price, committee size, etc.) — inherits OpenZeppelin v2's `Ownable` and exposes a single-step `transferOwnership`. If the owner passes a wrong `newOwner` address, ownership is irrecoverably lost and every `onlyOwner`-gated function (`setParam`, `setParamIn`) becomes permanently inaccessible, freezing all governance parameter updates forever.

---

### Finding Description

`GovParam` inherits `Ownable` from `contracts/libs/openzeppelin-contracts-v2/contracts/ownership/Ownable.sol`. The `transferOwnership` implementation is:

```solidity
function transferOwnership(address newOwner) public onlyOwner {
    _transferOwnership(newOwner);
}

function _transferOwnership(address newOwner) internal {
    require(newOwner != address(0), "Ownable: new owner is the zero address");
    emit OwnershipTransferred(_owner, newOwner);
    _owner = newOwner;   // ← immediate, irreversible
}
```

The only guard is a zero-address check. There is no pending-owner state, no acceptance step, and no recovery path. A single call with a mistyped or inaccessible address atomically and permanently replaces `_owner`.

`GovParam` exposes two owner-only write functions:

- `setParam(string name, bool exists, bytes val, uint256 activation)` — sets a governance parameter at a future block
- `setParamIn(string name, bool exists, bytes val, uint256 relativeActivation)` — same with relative block offset

Both are gated `onlyOwner`. After a bad `transferOwnership`, neither can ever be called again.

The same single-step pattern is present in `Registry` (KIP-149), `Bridge`, `PublicDelegation`, `CnStakingV4`, and `SimpleBlsRegistry`, but `GovParam` carries the highest systemic impact because it is the canonical source for all chain-economic parameters read by the consensus and reward engines.

---

### Impact Explanation

If `GovParam` ownership is transferred to an uncontrolled address:

- `reward.mintingamount` — KAIA block reward minting amount — can never be changed.
- `reward.ratio` / `reward.kip82ratio` — reward split between CN/KGF/KIR — permanently frozen.
- `governance.unitprice` — base gas price — permanently frozen.
- `istanbul.committeesize` / `istanbul.epoch` — validator committee parameters — permanently frozen.
- `kip71.*` — EIP-1559-style base-fee parameters — permanently frozen.

This constitutes permanent corruption of the governance parameter state, matching the allowed impact: *"Bridge, governance, validator, or system-contract privilege escalation that changes protected chain state or asset ownership."*

---

### Likelihood Explanation

Low. The trigger requires the current `GovParam` owner to call `transferOwnership` with an incorrect address (typo, copy-paste error, compromised key used to set a burner address, or a multisig migration that fails mid-flight). This is the same likelihood classification as the external report: low probability, catastrophic and irreversible consequence.

---

### Recommendation

Replace the inherited `Ownable.transferOwnership` in `GovParam` (and `Registry`, `Bridge`, `PublicDelegation`, `CnStakingV4`) with a two-step pattern:

```solidity
address private _pendingOwner;

function transferOwnership(address newOwner) public onlyOwner {
    _pendingOwner = newOwner;
    emit OwnershipTransferStarted(owner(), newOwner);
}

function acceptOwnership() public {
    require(msg.sender == _pendingOwner, "not pending owner");
    emit OwnershipTransferred(_owner, _pendingOwner);
    _owner = _pendingOwner;
    _pendingOwner = address(0);
}
```

OpenZeppelin v4+ provides `Ownable2Step` which implements exactly this pattern. Until the upgrade, operators should use a multisig with a time-lock for any ownership transfer of `GovParam`.

---

### Proof of Concept

1. Deploy `GovParam` with `owner = Alice`.
2. Alice calls `transferOwnership(0xDEAD...BEEF)` where `0xDEAD...BEEF` is a mistyped address with no known private key.
3. `_owner` is immediately set to `0xDEAD...BEEF`. Transaction succeeds.
4. Alice calls `setParam("reward.mintingamount", true, abi.encode(newAmount), block.number + 100)`.
5. Transaction reverts: `"Ownable: caller is not the owner"`.
6. No further governance parameter can ever be updated. The chain's minting amount, reward ratios, gas price, and committee parameters are permanently frozen at their last-set values. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/ownership/Ownable.sol (L63-74)
```text
    function transferOwnership(address newOwner) public onlyOwner {
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     */
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
```

**File:** contracts/bindings/gov/GovParam.go (L520-539)
```go
// SetParam is a paid mutator transaction binding the contract method 0x3f8aa624.
//
// Solidity: function setParam(string name, bool exists, bytes val, uint256 activation) returns()
func (_GovParam *GovParamTransactor) SetParam(opts *bind.TransactOpts, name string, exists bool, val []byte, activation *big.Int) (*types.Transaction, error) {
	return _GovParam.contract.Transact(opts, "setParam", name, exists, val, activation)
}

// SetParam is a paid mutator transaction binding the contract method 0x3f8aa624.
//
// Solidity: function setParam(string name, bool exists, bytes val, uint256 activation) returns()
func (_GovParam *GovParamSession) SetParam(name string, exists bool, val []byte, activation *big.Int) (*types.Transaction, error) {
	return _GovParam.Contract.SetParam(&_GovParam.TransactOpts, name, exists, val, activation)
}

// SetParam is a paid mutator transaction binding the contract method 0x3f8aa624.
//
// Solidity: function setParam(string name, bool exists, bytes val, uint256 activation) returns()
func (_GovParam *GovParamTransactorSession) SetParam(name string, exists bool, val []byte, activation *big.Int) (*types.Transaction, error) {
	return _GovParam.Contract.SetParam(&_GovParam.TransactOpts, name, exists, val, activation)
}
```

**File:** contracts/bindings/gov/GovParam.go (L562-581)
```go
// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_GovParam *GovParamTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _GovParam.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_GovParam *GovParamSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _GovParam.Contract.TransferOwnership(&_GovParam.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_GovParam *GovParamTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _GovParam.Contract.TransferOwnership(&_GovParam.TransactOpts, newOwner)
}
```

**File:** kaiax/gov/param.go (L181-191)
```go
	RewardDeferredTxFee            ParamName = "reward.deferredtxfee"
	RewardKip82Ratio               ParamName = "reward.kip82ratio"
	RewardMintingAmount            ParamName = "reward.mintingamount"
	RewardMinimumStake             ParamName = "reward.minimumstake"
	RewardProposerUpdateInterval   ParamName = "reward.proposerupdateinterval"
	RewardRatio                    ParamName = "reward.ratio"
	RewardStakingRewardThreshold   ParamName = "reward.stakingrewardthreshold"
	RewardStakingUpdateInterval    ParamName = "reward.stakingupdateinterval"
	RewardUseFlexReward            ParamName = "reward.useflexreward"
	RewardUseGiniCoeff             ParamName = "reward.useginicoeff"
)
```
