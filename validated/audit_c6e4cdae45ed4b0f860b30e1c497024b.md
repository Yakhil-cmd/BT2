### Title
Stale Operator Retains Bridge Value-Transfer Privilege After `transferOwnership` — (`contracts/service_chain/bridge/BridgeOperator.sol`)

---

### Summary

`BridgeOperator.sol` registers `msg.sender` as an operator in its constructor. The inherited `Ownable.transferOwnership()` only updates `_owner`; it never removes the previous owner from the `operators` mapping. After ownership is transferred, the previous owner remains a fully-privileged operator and can unilaterally call `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` to redirect bridge-held KLAY and bridged tokens to any address of their choosing.

---

### Finding Description

`BridgeOperator` is constructed with the deployer automatically inserted into the `operators` mapping and `operatorList` array, and with both vote thresholds set to `1`:

```solidity
// BridgeOperator.sol constructor (lines 54-61)
constructor() internal {
    for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
        operatorThresholds[uint8(i)] = 1;   // threshold = 1 by default
    }
    operators[msg.sender] = true;
    operatorList.push(msg.sender);
}
``` [1](#0-0) 

The `onlyOperators` modifier gates all value-transfer handle functions:

```solidity
modifier onlyOperators() {
    require(operators[msg.sender], "msg.sender is not an operator");
    _;
}
``` [2](#0-1) 

`transferOwnership` is inherited verbatim from OpenZeppelin `Ownable` and is **not overridden** in `BridgeOperator`. It only writes to `_owner`:

```solidity
function _transferOwnership(address newOwner) internal {
    require(newOwner != address(0), "Ownable: new owner is the zero address");
    emit OwnershipTransferred(_owner, newOwner);
    _owner = newOwner;   // operators mapping is untouched
}
``` [3](#0-2) 

After `transferOwnership(newOwner)` executes:

- `_owner` → `newOwner` (can call `registerOperator`, `deregisterOperator`, `setOperatorThreshold`)
- `operators[oldOwner]` → **still `true`** (can call every `onlyOperators` function)
- `operators[newOwner]` → **`false`** (new owner is not an operator by default)

With the default threshold of `1`, the stale operator can single-handedly satisfy `_voteValueTransfer` and trigger the actual asset transfer in `handleKLAYTransfer`:

```solidity
function handleKLAYTransfer(
    bytes32 _requestTxHash,
    address _from,
    address payable _to,   // attacker-controlled recipient
    uint256 _value,
    uint64 _requestedNonce,
    uint64 _requestedBlockNumber,
    bytes memory _extraData
)
    public
    onlyOperators
    nonReentrant
{
    _lowerHandleNonceCheck(_requestedNonce);
    if (!_voteValueTransfer(_requestedNonce)) { return; }
    ...
    (bool ok, ) = _to.call.value(_value)("");   // KLAY sent to attacker
    require(ok, "handleKLAYTransfer: transfer failed");
}
``` [4](#0-3) 

The same pattern applies to `handleERC20Transfer` (mints or transfers ERC20 tokens to `_to`): [5](#0-4) 

The stale operator can also call `setKLAYFee` / `setERC20Fee` (both `onlyOperators`) to manipulate bridge fees.

---

### Impact Explanation

The previous bridge owner retains the ability to:

1. **Drain KLAY** from the bridge by calling `handleKLAYTransfer` with `_to = attacker_address` and any unclosed nonce.
2. **Drain bridged ERC20 tokens** via `handleERC20Transfer` with `_to = attacker_address`.
3. **Drain bridged ERC721 tokens** via `handleERC721Transfer`.
4. **Manipulate fees** via `setKLAYFee` / `setERC20Fee`.

This is an unauthorized transfer of KAIA and bridged assets from a system-managed bridge contract, matching the allowed impact gate.

---

### Likelihood Explanation

`transferOwnership` is a standard, documented function exposed in the Go bindings (`contracts/bindings/bridge/bridge.go`, line 1795–1813) and is the natural mechanism for rotating the bridge operator key (e.g., after a key compromise or operational handover). Any operator who calls it without also calling `deregisterOperator(oldOwner)` in the same transaction leaves the bridge permanently exposed. Because the new owner is not automatically added to `operators`, they may not even notice the asymmetry until funds are drained. [6](#0-5) 

---

### Recommendation

Override `transferOwnership` in `BridgeOperator` to atomically remove the old owner from `operators` and add the new owner:

```solidity
function transferOwnership(address newOwner) public onlyOwner {
    address oldOwner = owner();

    // Remove old owner from operators if present
    if (operators[oldOwner]) {
        delete operators[oldOwner];
        for (uint i = 0; i < operatorList.length; i++) {
            if (operatorList[i] == oldOwner) {
                operatorList[i] = operatorList[operatorList.length - 1];
                operatorList.length--;
                break;
            }
        }
        emit OperatorDeregistered(oldOwner);
    }

    // Add new owner as operator if not already registered
    if (!operators[newOwner]) {
        require(operatorList.length < MAX_OPERATOR, "max operator limit");
        operators[newOwner] = true;
        operatorList.push(newOwner);
        emit OperatorRegistered(newOwner);
    }

    super.transferOwnership(newOwner);
}
```

---

### Proof of Concept

```
State before:
  owner()          = Alice
  operators[Alice] = true
  operatorThresholds[ValueTransfer] = 1
  bridge.balance   = 1000 KLAY

Step 1: Alice calls transferOwnership(Bob)
  → _owner = Bob
  → operators[Alice] = true  (unchanged — BUG)
  → operators[Bob]   = false (Bob is not an operator)

Step 2: Alice (stale operator) calls:
  handleKLAYTransfer(
      txHash = <any unused hash>,
      _from  = <any address>,
      _to    = Alice,          // attacker-controlled
      _value = 1000 KLAY,
      _requestedNonce = <any valid unclosed nonce>,
      ...
  )
  → _voteValueTransfer passes (threshold=1, Alice's vote counts)
  → closedValueTransferVotes[nonce] = true
  → 1000 KLAY sent to Alice

Result: Alice drains the bridge after transferring ownership to Bob.
        Bob (new owner) cannot prevent this in the same block.
``` [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L54-67)
```text
    constructor() internal {
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }

        operators[msg.sender] = true;
        operatorList.push(msg.sender);
    }

    modifier onlyOperators()
    {
        require(operators[msg.sender], "msg.sender is not an operator");
        _;
    }
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/ownership/Ownable.sol (L70-74)
```text
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-100)
```text
    function handleKLAYTransfer(
        bytes32 _requestTxHash,
        address _from,
        address payable _to,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
        nonReentrant
    {
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);

        emit HandleValueTransfer(
            _requestTxHash,
            TokenType.KLAY,
            _from,
            _to,
            address(0),
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-73)
```text
    function handleERC20Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
    {
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);

        emit HandleValueTransfer(
            _requestTxHash,
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
    }
```

**File:** contracts/bindings/bridge/bridge.go (L1795-1813)
```go
// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Bridge *BridgeTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _Bridge.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Bridge *BridgeSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Bridge.Contract.TransferOwnership(&_Bridge.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Bridge *BridgeTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Bridge.Contract.TransferOwnership(&_Bridge.TransactOpts, newOwner)
```
