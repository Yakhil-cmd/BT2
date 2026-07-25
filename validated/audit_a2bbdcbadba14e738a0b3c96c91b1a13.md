### Title
Old Bridge Owner Retains Operator Privileges After `transferOwnership`, Enabling Unauthorized KLAY/ERC20 Drain — (`contracts/service_chain/bridge/BridgeOperator.sol`)

### Summary

`BridgeOperator.sol` auto-registers the deployer as an operator in its constructor. When `transferOwnership` is called (inherited from `Ownable`), only `_owner` is updated; the old owner's entry in `operators[oldOwner]` and `operatorList` is never cleared. Because `handleKLAYTransfer` and `handleERC20Transfer` are gated by `onlyOperators` (not `onlyOwner`), the old owner retains the ability to unilaterally execute bridge value transfers after the ownership handoff, draining KLAY or minting/transferring ERC20 tokens held by the bridge.

### Finding Description

`BridgeOperator`'s constructor unconditionally registers `msg.sender` as an operator: [1](#0-0) 

`transferOwnership` is the standard OpenZeppelin `Ownable` implementation and only reassigns `_owner`: [2](#0-1) 

It does not touch `operators` or `operatorList`. After the call, `operators[oldOwner]` remains `true` and `oldOwner` remains in `operatorList`.

The `onlyOperators` modifier checks only the `operators` mapping: [3](#0-2) 

`handleKLAYTransfer` and `handleERC20Transfer` are both gated by this modifier: [4](#0-3) [5](#0-4) 

The default `operatorThresholds[ValueTransfer]` is `1`, so a single operator vote immediately executes the transfer. The old owner, still in `operators`, can call `handleKLAYTransfer` or `handleERC20Transfer` alone and the vote threshold is immediately met.

The `deregisterOperator` function that would remove the old owner is itself `onlyOwner`: [6](#0-5) 

The new owner must know to call it. There is no automatic cleanup, no event that signals the old owner is still an operator, and no guard in `transferOwnership` that prevents this state from persisting.

The comment in `deregisterOperator` acknowledges that outstanding votes by a deregistered operator are not revoked, but the more fundamental issue is that the old owner is never deregistered at all during ownership transfer: [7](#0-6) 

### Impact Explanation

The old owner can call `handleKLAYTransfer` directing the bridge's KLAY balance to an arbitrary `_to` address, or call `handleERC20Transfer` to mint (in `modeMintBurn` mode) or transfer ERC20 tokens held by the bridge. Both result in unauthorized movement of bridged assets. With the default threshold of 1, no other operator vote is needed.

### Likelihood Explanation

`transferOwnership` is a standard administrative operation. Any bridge deployment that changes hands (e.g., protocol upgrade, key rotation, multisig migration) triggers this path. The new owner has no on-chain signal that the old owner is still an operator; the only way to discover it is to read `operatorList` off-chain. The old owner's motivation to exploit this is high if the bridge holds significant KLAY or ERC20 value.

### Recommendation

Override `transferOwnership` in `BridgeOperator` to atomically deregister the old owner from `operators` and `operatorList` before setting the new owner, and register the new owner as an operator if desired. Alternatively, emit a warning event and require the new owner to explicitly confirm operator cleanup before the bridge resumes operation.

### Proof of Concept

1. Alice deploys `Bridge`. Constructor sets `operators[Alice] = true`, `operatorList = [Alice]`, `operatorThresholds[ValueTransfer] = 1`.
2. Alice calls `transferOwnership(Bob)`. `_owner` becomes Bob. `operators[Alice]` is still `true`.
3. Alice calls `handleKLAYTransfer(txHash, from, Alice, 100 ether, nonce, blockNum, "")`. The `onlyOperators` check passes (`operators[Alice] == true`). `_voteValueTransfer` returns `true` (threshold 1 met). The bridge sends 100 ether to Alice.
4. Bob, the new owner, never knew Alice was still an operator and never called `deregisterOperator(Alice)`.

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L54-61)
```text
    constructor() internal {
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }

        operators[msg.sender] = true;
        operatorList.push(msg.sender);
    }
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L63-67)
```text
    modifier onlyOperators()
    {
        require(operators[msg.sender], "msg.sender is not an operator");
        _;
    }
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L146-158)
```text
    // deregisterOperator deregisters the operator.
    //
    // Note that outstanding votes by the deregistered operator are not revoked.
    // This enables a subtle counterintuitive scenario.
    //
    // Suppose there are two operators A, B and C with threshold 2.
    // 1. Operator A votes on nonce N
    // 2. Owner deregisters A
    // 3. Operator B votes on nonce N, thereby executing the request N.
    // In this case the request was executed with A's vote after A is deregistered.
    //
    // The Owner shall recognize this issue and expect that operator deregistration
    // takes some time to be fully effective.
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L159-174)
```text
    function deregisterOperator(address _operator)
    external
    onlyOwner
    {
        require(operators[_operator]);
        delete operators[_operator];

        for (uint i = 0; i < operatorList.length; i++) {
           if (operatorList[i] == _operator) {
               operatorList[i] = operatorList[operatorList.length-1];
               operatorList.length--;
               break;
           }
        }
        emit OperatorDeregistered(_operator);
    }
```

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
