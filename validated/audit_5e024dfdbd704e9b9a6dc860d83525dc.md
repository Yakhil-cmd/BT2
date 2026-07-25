The analysis is complete. I have a clear finding.

---

### Title
Bridge `handle*Transfer` Functions Execute Asset Transfers When Bridge Is Stopped — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

### Summary
The `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` functions in Kaia's service-chain bridge contracts do not check the `isRunning` flag before executing asset transfers. When the bridge owner sets `isRunning = false` to halt bridge operations, operators can still call these functions to push KLAY, ERC20 tokens, and ERC721 tokens out of the bridge to arbitrary recipients, directly undermining the emergency-stop mechanism.

### Finding Description

`BridgeTransfer.sol` defines `isRunning = true` as the bridge's operational state flag, and `setRunningStatus(false)` / `start(false)` as the owner-only mechanism to halt all bridge activity. [1](#0-0) 

The **request-side** functions (user-facing) all correctly enforce this flag:

- `_requestKLAYTransfer`: `require(isRunning, "stopped bridge");` [2](#0-1) 

- `_requestERC20Transfer`: `require(isRunning, "stopped bridge");` [3](#0-2) 

- `_requestERC721Transfer`: `require(isRunning, "stopped bridge");` [4](#0-3) 

However, the **handle-side** functions (operator-facing, which actually disburse assets) have **no `isRunning` check**:

`handleKLAYTransfer` — only guarded by `onlyOperators` and `nonReentrant`: [5](#0-4) 

It then executes a live KLAY transfer: [6](#0-5) 

`handleERC20Transfer` — only guarded by `onlyOperators`, then mints or transfers ERC20 tokens: [7](#0-6) [8](#0-7) 

`handleERC721Transfer` — only guarded by `onlyOperators`, then mints or transfers ERC721 tokens: [9](#0-8) [10](#0-9) 

### Impact Explanation

When the bridge owner calls `setRunningStatus(false)` to halt the bridge during an emergency (e.g., a discovered exploit, a counterpart chain incident, or a governance action), the intent is to freeze all cross-chain asset movement. However, any registered operator can still call `handleKLAYTransfer`, `handleERC20Transfer`, or `handleERC721Transfer` to:

- Send KLAY held in the bridge contract to arbitrary `_to` addresses
- Mint ERC20 tokens (in `modeMintBurn` mode) or transfer locked ERC20 tokens to arbitrary recipients
- Mint ERC721 tokens or transfer locked NFTs to arbitrary recipients

The corrupted values are: the bridge's KLAY balance, ERC20 token balances, and ERC721 token custody — all of which can be drained or minted against the owner's intent while `isRunning == false`.

### Likelihood Explanation

Operators are semi-trusted entities registered by the bridge owner. There can be multiple operators with a threshold voting system (`_voteValueTransfer`). A single operator who has accumulated enough votes (or meets the threshold alone) can complete a handle transfer. The owner's ability to pause the bridge is the primary emergency control, and its asymmetric enforcement (blocks users, not operators) means any operator acting during a pause — whether maliciously or by mistake — bypasses the intended freeze.

### Recommendation

Add an `isRunning` check to all three handle functions, consistent with the pattern already used on the request side:

```solidity
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    require(isRunning, "stopped bridge");  // ADD THIS
    ...
}

function handleERC20Transfer(...) public onlyOperators {
    require(isRunning, "stopped bridge");  // ADD THIS
    ...
}

function handleERC721Transfer(...) public onlyOperators {
    require(isRunning, "stopped bridge");  // ADD THIS
    ...
}
```

### Proof of Concept

1. Bridge owner deploys bridge with `isRunning = true`.
2. Owner registers operator `op` and configures threshold = 1.
3. A cross-chain KLAY transfer request is pending (nonce N, value 100 KLAY locked in bridge).
4. Owner detects an incident and calls `setRunningStatus(false)` → `isRunning = false`.
5. Any user calling `requestKLAYTransfer` now reverts with `"stopped bridge"`. ✓
6. Operator `op` calls `handleKLAYTransfer(txHash, from, victim, 100 ether, N, blockNum, "")`.
7. `_lowerHandleNonceCheck` passes, `_voteValueTransfer` passes (threshold=1), `_to.call.value(100 ether)("")` executes.
8. 100 KLAY is transferred out of the bridge while `isRunning == false`, directly contradicting the owner's emergency stop. [11](#0-10) [12](#0-11)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L27-28)
```text
    bool public modeMintBurn = false;
    bool public isRunning = true;
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L50-57)
```text
    // setRunningStatus can allow or disallow the value transfer request.
    function setRunningStatus(bool _status)
        public
        onlyOwner
    {
        isRunning = _status;
        emit RunningStatusChanged(_status);
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L108-108)
```text
        require(isRunning, "stopped bridge");
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-44)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L88-88)
```text
        require(isRunning, "stopped bridge");
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L29-41)
```text
    function handleERC721Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _tokenId,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        string memory _tokenURI,
        bytes memory _extraData
    )
        public
        onlyOperators
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L85-85)
```text
        require(isRunning, "stopped bridge");
```
