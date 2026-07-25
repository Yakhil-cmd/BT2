The `isRunning` flag in `BridgeTransfer.sol` is checked in all **outbound** (request) paths but is **never checked** in any **inbound** (handle) path. This is the direct Kaia analog of the external bug.

---

### Title
`isRunning` Stop Flag Not Enforced in `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

### Summary

The bridge owner can call `setRunningStatus(false)` to halt the bridge in an emergency. However, the `isRunning` flag is only checked in the outbound request functions. All three inbound `handleXXXTransfer` functions — which actually move KAIA, ERC20, and ERC721 tokens out of the bridge to recipients — do not check `isRunning`. Bridge operators can therefore continue draining bridged assets from a stopped bridge.

### Finding Description

`BridgeTransfer.sol` declares `bool public isRunning = true` and exposes `setRunningStatus(bool)` (`onlyOwner`) to halt the bridge. [1](#0-0) 

The outbound paths correctly enforce the flag:

- `_requestKLAYTransfer` — `require(isRunning, "stopped bridge")` [2](#0-1) 
- `_requestERC20Transfer` — `require(isRunning, "stopped bridge")` [3](#0-2) 
- `_requestERC721Transfer` — `require(isRunning, "stopped bridge")` [4](#0-3) 

The inbound handle functions have **no `isRunning` check**:

- `handleKLAYTransfer` — transfers KAIA to `_to` with no stop-flag guard [5](#0-4) 
- `handleERC20Transfer` — mints or transfers ERC20 to `_to` with no stop-flag guard [6](#0-5) 
- `handleERC721Transfer` — mints or transfers ERC721 to `_to` with no stop-flag guard [7](#0-6) 

### Impact Explanation

When the bridge owner calls `setRunningStatus(false)` (or `start(false)`) to halt the bridge — e.g., in response to a security incident on the counterpart chain — bridge operators can still call `handleKLAYTransfer`, `handleERC20Transfer`, or `handleERC721Transfer` to move KAIA, ERC20 tokens, or ERC721 NFTs out of the bridge contract to arbitrary recipients. In `modeMintBurn` mode, operators can also trigger unbounded minting of ERC20/ERC721 tokens on the destination side. The owner's emergency stop provides no protection against inbound asset movement.

**Corrupted value:** KAIA balance of the bridge contract, ERC20 token balances, ERC721 ownership — all can be altered by operators after the owner has set `isRunning = false`.

### Likelihood Explanation

The operators are a distinct, semi-trusted role from the owner. The owner stops the bridge precisely because they distrust the current state (e.g., a compromised counterpart bridge, a replay attack, or an oracle manipulation). Operators — who may themselves be compromised or acting on stale/malicious counterpart-chain events — can continue executing handle transfers. The trigger requires only a valid operator key, which is a reachable semi-trusted precondition explicitly within scope.

### Recommendation

Add `require(isRunning, "stopped bridge")` at the top of each handle function, mirroring the guard already present in the request functions:

```solidity
// In handleKLAYTransfer, handleERC20Transfer, handleERC721Transfer:
require(isRunning, "stopped bridge");
```

Alternatively, extract the check into a shared internal function or modifier in `BridgeTransfer.sol` and apply it to all six transfer entry points.

### Proof of Concept

1. Owner deploys bridge, operators are registered.
2. A security incident occurs on the counterpart chain; owner calls `bridge.start(false)` → `isRunning = false`.
3. Operator calls `bridge.handleKLAYTransfer(txHash, from, attacker, 1000 ether, 0, blockNum, "")`.
4. No revert: `isRunning` is never read in `handleKLAYTransfer`. The bridge sends 1000 KAIA to `attacker`.
5. Repeat for `handleERC20Transfer` and `handleERC721Transfer` to drain all bridged assets.

The existing test at `contracts/test/Bridge/bridge.test.ts` line 851–858 confirms that `start(false)` blocks the fallback/request path but contains no test asserting that handle paths are also blocked — consistent with the missing guard. [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L28-57)
```text
    bool public isRunning = true;

    uint64 public requestNonce; // the number of value transfer request that this contract received.
    uint64 public lowerHandleNonce; // a minimum nonce of a value transfer request that will be handled.
    uint64 public upperHandleNonce; // a maximum nonce of the counterpart bridge's value transfer request that is handled.
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
    mapping(uint64 => uint64) public handleNoncesToBlockNums;  // <request nonce> => <request blockNum>

    event RunningStatusChanged(bool _status);

    using SafeMath for uint256;

    enum TokenType {
        KLAY,
        ERC20,
        ERC721
    }

    constructor(bool _modeMintBurn) BridgeFee(address(0)) internal {
        modeMintBurn = _modeMintBurn;
    }

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-108)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
        require(isRunning, "stopped bridge");
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-88)
```text
    function _requestERC20Transfer(
        address _tokenAddress,
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L29-71)
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
            TokenType.ERC721,
            _from,
            _to,
            _tokenAddress,
            _tokenId,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L74-85)
```text
    function _requestERC721Transfer(
        address _tokenAddress,
        address _from,
        address _to,
        uint256 _tokenId,
        bytes memory _extraData
    )
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
```

**File:** contracts/test/Bridge/bridge.test.ts (L851-858)
```typescript
    it("stopped bridge", async function() {
      const fixture = await loadFixture(deployBridgeConfiguredFixture);
      const { bridge, owner, user1 } = fixture;

      await bridge.connect(owner).start(false);
      expect(bridge.connect(user1).fallback({value: parseEther("1.0")}))
        .to.be.revertedWith("stopped bridge");
    });
```
