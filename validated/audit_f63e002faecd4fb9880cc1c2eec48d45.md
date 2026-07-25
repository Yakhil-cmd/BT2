### Title
`handleERC20Transfer` / `handleERC721Transfer` / `handleKLAYTransfer` Bypass Both Global `isRunning` Stop and Token-Specific Lock — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`, `BridgeTransferKLAY.sol`)

---

### Summary

The Kaia service-chain bridge has two independent halt controls: a global `isRunning` flag (stops all value-transfer requests) and per-token `lockedTokens[token]` / `isLockedKLAY` flags (stops transfers of a specific asset). The outbound `request*Transfer` functions enforce both controls. The inbound `handle*Transfer` functions enforce neither, so bridge operators can mint or transfer bridged assets to arbitrary recipients even after the bridge owner has issued an emergency stop or locked a specific token.

---

### Finding Description

`BridgeTransfer.isRunning` is the global bridge halt: [1](#0-0) 

`BridgeTokens.lockedTokens` is the per-token halt: [2](#0-1) 

`BridgeTransferKLAY.isLockedKLAY` is the KLAY-specific halt: [3](#0-2) 

Every outbound path enforces both controls. For example, `_requestERC20Transfer` applies `onlyUnlockedToken` and then `require(isRunning, "stopped bridge")`: [4](#0-3) 

`_requestKLAYTransfer` applies `unlockedKLAY` and then `require(isRunning, "stopped bridge")`: [5](#0-4) 

The inbound handle functions carry only `onlyOperators` (and `nonReentrant` for KLAY). Neither `isRunning` nor any lock is checked:

`handleERC20Transfer` — no `isRunning`, no `onlyRegisteredToken`, no `onlyUnlockedToken`: [6](#0-5) 

`handleERC721Transfer` — no `isRunning`, no `onlyRegisteredToken`, no `onlyUnlockedToken`: [7](#0-6) 

`handleKLAYTransfer` — no `isRunning`, no `unlockedKLAY`: [8](#0-7) 

The actual asset-moving lines inside those functions execute unconditionally once the vote threshold is met:

ERC20 mint/transfer: [9](#0-8) 

KLAY transfer: [10](#0-9) 

---

### Impact Explanation

When the bridge owner calls `setRunningStatus(false)` or `lockToken(addr)` / `lockKLAY()` to halt the bridge in an emergency (e.g., a counterpart-chain exploit producing fraudulent request events), bridge operators can still call `handleERC20Transfer`, `handleERC721Transfer`, or `handleKLAYTransfer` to:

- **Mint** arbitrary amounts of a bridged ERC-20 token to any address (in `modeMintBurn` mode), or
- **Transfer** tokens / KLAY held in the bridge contract to any address (in lock mode).

The bridge owner's emergency stop is fully bypassed. Assets (KLAY, bridged ERC-20, bridged ERC-721) are transferred or minted to recipients despite the halt, directly matching the "unauthorized transfer, mint, or unlock affecting KAIA or bridged assets" impact gate.

---

### Likelihood Explanation

Bridge operators are semi-trusted: they are registered by the owner but are distinct accounts. The owner's ability to stop the bridge is the primary emergency-response mechanism. Any operator (threshold of registered operators, typically 2-of-N) can call a handle function at any time. If the bridge is stopped precisely because operators or the counterpart chain are suspected of misbehavior, those same operators can still drain or mint assets. The trigger requires no special privilege beyond the operator role, which is the normal operational role for bridge relayers.

---

### Recommendation

Add `isRunning`, `onlyRegisteredToken`, and `onlyUnlockedToken` / `unlockedKLAY` guards to all three handle functions, mirroring the request-side enforcement:

```solidity
// BridgeTransferERC20.sol
function handleERC20Transfer(...) public onlyOperators onlyRegisteredToken(_tokenAddress) onlyUnlockedToken(_tokenAddress) {
    require(isRunning, "stopped bridge");
    ...
}

// BridgeTransferERC721.sol
function handleERC721Transfer(...) public onlyOperators onlyRegisteredToken(_tokenAddress) onlyUnlockedToken(_tokenAddress) {
    require(isRunning, "stopped bridge");
    ...
}

// BridgeTransferKLAY.sol
function handleKLAYTransfer(...) public onlyOperators unlockedKLAY nonReentrant {
    require(isRunning, "stopped bridge");
    ...
}
```

---

### Proof of Concept

1. Bridge owner calls `setRunningStatus(false)` — bridge is globally stopped.
2. Bridge owner calls `lockToken(erc20Addr)` — that ERC-20 is specifically locked.
3. A threshold of operators call `handleERC20Transfer(txHash, attacker, victim, erc20Addr, 1e18, nonce, blockNum, "")`.
4. Because `handleERC20Transfer` has no `isRunning` or `onlyUnlockedToken` check, the vote succeeds and `ERC20Mintable(erc20Addr).mint(victim, 1e18)` (or `safeTransfer`) executes.
5. Tokens are minted/transferred despite both the global stop and the per-token lock being active.

The same sequence applies to `handleKLAYTransfer` after `lockKLAY()` and `setRunningStatus(false)`, draining KLAY from the bridge contract.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L28-28)
```text
    bool public isRunning = true;
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L25-25)
```text
    mapping(address => bool) public lockedTokens;
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L24-24)
```text
    bool public isLockedKLAY;
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-73)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L98-99)
```text
        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-43)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-88)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
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
