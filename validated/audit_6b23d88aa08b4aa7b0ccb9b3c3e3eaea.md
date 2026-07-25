### Title
`BridgeTransfer` Defines `isRunning` Emergency Stop But `handle*Transfer` Functions Never Check It, Allowing Asset Drain When Bridge Is Stopped — (`contracts/service_chain/bridge/BridgeTransfer.sol`)

---

### Summary

`BridgeTransfer` declares an `isRunning` flag and a `setRunningStatus()` function so the owner can halt the bridge in an emergency. The `_request*Transfer` functions on all three asset paths (KLAY, ERC20, ERC721) correctly enforce `require(isRunning, "stopped bridge")`. However, the three `handle*Transfer` functions — which actually move assets **out** of the bridge to recipients — never check `isRunning`. When the owner stops the bridge, operators can still call `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` to drain KAIA and bridged tokens.

---

### Finding Description

`BridgeTransfer` stores the emergency-stop flag and its setter: [1](#0-0) 

The request (deposit) path on every asset type enforces the guard:

- `BridgeTransferKLAY._requestKLAYTransfer`: [2](#0-1) 
- `BridgeTransferERC20._requestERC20Transfer`: [3](#0-2) 
- `BridgeTransferERC721._requestERC721Transfer`: [4](#0-3) 

The handle (withdrawal) path on every asset type has **no** `isRunning` check:

- `handleKLAYTransfer` (only `onlyOperators` + `nonReentrant`): [5](#0-4) 
- `handleERC20Transfer` (only `onlyOperators`): [6](#0-5) 
- `handleERC721Transfer` (only `onlyOperators`): [7](#0-6) 

---

### Impact Explanation

When the bridge owner calls `setRunningStatus(false)` to halt the bridge — the primary emergency response — the `isRunning` flag stops new cross-chain transfer requests from being created. However, any operator can still call `handleKLAYTransfer`, `handleERC20Transfer`, or `handleERC721Transfer` with any valid (or previously queued) nonce and drain KAIA and bridged ERC20/ERC721 tokens from the bridge contract. The emergency stop is completely ineffective on the withdrawal side, which is the side that moves assets.

Exact corrupted values: KAIA balance of the bridge contract (`_to.call.value(_value)("")` at line 98 of `BridgeTransferKLAY.sol`), ERC20 token balances (`IERC20.safeTransfer` at line 71 of `BridgeTransferERC20.sol`), and ERC721 token ownership (`IERC721.transferFrom` at line 69 of `BridgeTransferERC721.sol`) are all modified despite `isRunning == false`.

---

### Likelihood Explanation

The bridge operator set is semi-trusted but distinct from the owner. The entire motivation for `isRunning` is to protect against scenarios where operators or the counterpart chain are compromised. An operator (or a compromised operator key) can call any `handle*Transfer` function at any time regardless of the stopped state. No additional privilege beyond the `onlyOperators` role — which is a normal operational role — is required.

---

### Recommendation

Add `require(isRunning, "stopped bridge")` to all three handle functions, or extract it into a shared modifier and apply it uniformly:

```diff
// BridgeTransferKLAY.sol
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
+   require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

// BridgeTransferERC20.sol
function handleERC20Transfer(...) public onlyOperators {
+   require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

// BridgeTransferERC721.sol
function handleERC721Transfer(...) public onlyOperators {
+   require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}
```

---

### Proof of Concept

1. Deploy the bridge (e.g., `BridgeTransferKLAY`) and fund it with KAIA via `chargeWithoutEvent()`.
2. Owner calls `setRunningStatus(false)` — bridge is now stopped.
3. Verify: `requestKLAYTransfer(...)` reverts with `"stopped bridge"`. ✓
4. Operator calls `handleKLAYTransfer(txHash, from, attacker, 1000 ether, nonce, blockNum, "")`.
5. Result: 1000 KAIA is transferred to `attacker` despite `isRunning == false`. The `isRunning` guard is completely bypassed on the withdrawal path.

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-74)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-109)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
        require(isRunning, "stopped bridge");
        require(msg.value > _feeLimit, "insufficient amount");
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-89)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
        require(_value > 0, "zero ERC20 token amount");
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L29-42)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L81-86)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
        (bool success, bytes memory uri) = _tokenAddress.call(abi.encodePacked(ERC721Metadata(_tokenAddress).tokenURI.selector, abi.encode(_tokenId)));
```
