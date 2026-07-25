### Title
`handleERC20Transfer` / `handleERC721Transfer` / `handleKLAYTransfer` bypass token lock and deregistration, enabling unauthorized mint or asset transfer — (File: `contracts/service_chain/bridge/BridgeTransferERC20.sol`, `contracts/service_chain/bridge/BridgeTransferERC721.sol`, `contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

The Kaia service-chain bridge enforces token-registration and lock checks only on the **outbound** (request) path, not on the **inbound** (handle) path. When the bridge owner locks or deregisters a token to halt transfers, operators can still call `handleERC20Transfer`, `handleERC721Transfer`, or `handleKLAYTransfer` to mint or transfer that token on the destination side, defeating the owner's protective action.

---

### Finding Description

**Outbound path — enforces token state:**

`_requestERC20Transfer` carries both `onlyRegisteredToken(_tokenAddress)` and `onlyUnlockedToken(_tokenAddress)` modifiers: [1](#0-0) 

`_requestERC721Transfer` carries the same two modifiers: [2](#0-1) 

`_requestKLAYTransfer` carries the `unlockedKLAY` modifier: [3](#0-2) 

**Inbound path — does NOT enforce token state:**

`handleERC20Transfer` carries only `onlyOperators`. There is no `onlyRegisteredToken` or `onlyUnlockedToken` check. It proceeds directly to mint or transfer: [4](#0-3) 

`handleERC721Transfer` is identical in structure — only `onlyOperators`, no token-state check: [5](#0-4) 

`handleKLAYTransfer` carries only `onlyOperators` + `nonReentrant`. The `isLockedKLAY` flag is never consulted: [6](#0-5) 

**The lock and deregistration primitives that are bypassed:**

`lockToken` sets `lockedTokens[_token] = true` to "prevent request token transferring," but this flag is never read by any handle function: [7](#0-6) 

`deregisterToken` clears `registeredTokens[_token]`, but again the handle functions never consult `registeredTokens`: [8](#0-7) 

`lockKLAY` sets `isLockedKLAY = true`, but `handleKLAYTransfer` never checks it: [9](#0-8) 

---

### Impact Explanation

| Scenario | Concrete corrupted value |
|---|---|
| `modeMintBurn = true`, token locked/deregistered | Operator calls `handleERC20Transfer` → `ERC20Mintable(_tokenAddress).mint(_to, _value)` executes → tokens minted on destination chain for a token the owner intended to halt |
| `modeMintBurn = false`, token locked/deregistered | Operator calls `handleERC20Transfer` → `IERC20(_tokenAddress).safeTransfer(_to, _value)` executes → bridge-held ERC20 balance drained |
| KLAY locked | Operator calls `handleKLAYTransfer` → `_to.call.value(_value)("")` executes → KLAY transferred out of bridge despite `isLockedKLAY = true` |
| ERC721, either mode | Same asymmetry: `handleERC721Transfer` mints or transfers NFTs for a locked/deregistered token |

The corrupted values are: unauthorized token mint supply, unauthorized reduction of bridge ERC20/KLAY reserves, and unauthorized NFT ownership transfer — all affecting bridged assets or system-managed funds. [10](#0-9) [11](#0-10) 

---

### Likelihood Explanation

The trigger requires a registered operator to call a handle function after the owner has locked or deregistered a token. Operators are semi-trusted bridge relayers registered by the owner. The scenario arises naturally when:

1. The owner locks or deregisters a token in response to a security incident (e.g., a compromised token contract or a bridge exploit in progress).
2. One or more operators — who may themselves be compromised, or who are simply replaying a legitimately queued cross-chain event — call `handleERC20Transfer` / `handleKLAYTransfer` for the affected token.
3. Because no guard exists on the handle path, the mint or transfer executes unconditionally.

The owner's protective action is therefore not atomic: locking/deregistering stops new outbound requests but leaves the inbound handle path fully open. Any operator active at the time of the lock can continue processing transfers indefinitely. [12](#0-11) 

---

### Recommendation

1. **`handleERC20Transfer`**: add `onlyRegisteredToken(_tokenAddress)` and `onlyUnlockedToken(_tokenAddress)` modifiers (or equivalent `require` statements) before the mint/transfer step.

2. **`handleERC721Transfer`**: same — add `onlyRegisteredToken(_tokenAddress)` and `onlyUnlockedToken(_tokenAddress)`.

3. **`handleKLAYTransfer`**: add `unlockedKLAY` modifier (or `require(!isLockedKLAY, "locked")`) before the KLAY transfer.

These additions mirror the guards already present on the request path and ensure that a single owner action (lock or deregister) atomically halts both directions of the bridge for the affected asset. [13](#0-12) [14](#0-13) 

---

### Proof of Concept

```
Setup
─────
1. Deploy Bridge in modeMintBurn=true.
2. Owner registers token T: registerToken(T, cT).
3. Owner registers operators op1, op2; sets threshold = 2.
4. Users bridge tokens normally via requestERC20Transfer.

Attack
──────
5. Owner discovers token T is compromised; calls lockToken(T).
   → lockedTokens[T] = true
   → _requestERC20Transfer now reverts with "locked token" ✓

6. op1 calls:
     handleERC20Transfer(txHash, from, victim, T, 1_000_000e18, nonce, blockNum, "")
   → onlyOperators: passes (op1 is still registered)
   → _lowerHandleNonceCheck: passes
   → _voteValueTransfer: records op1's vote, threshold not yet met → returns false → function returns

7. op2 calls the same handleERC20Transfer with identical arguments.
   → _voteValueTransfer: threshold met → returns true
   → NO check on lockedTokens[T] or registeredTokens[T]
   → ERC20Mintable(T).mint(victim, 1_000_000e18) executes
   → 1,000,000 tokens minted on destination chain despite the lock

Result
──────
Token T is locked on the outbound side but 1,000,000 tokens are
minted on the inbound side. The owner's protective lock is bypassed.
The same attack works with deregisterToken(T) and with lockKLAY()
+ handleKLAYTransfer draining the bridge's KLAY balance.
``` [4](#0-3) [15](#0-14) [5](#0-4)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L42-73)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-87)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L40-71)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L81-84)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L29-37)
```text
    modifier lockedKLAY {
        require(isLockedKLAY, "unlocked");
        _;
    }

    modifier unlockedKLAY {
        require(!isLockedKLAY, "locked");
        _;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L39-48)
```text
    // lockKLAY can to prevent request KLAY transferring.
    function lockKLAY()
        external
        onlyOwner
        unlockedKLAY
    {
        isLockedKLAY = true;

        emit KLAYLocked();
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L61-100)
```text
    // handleKLAYTransfer sends the KLAY by the request.
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-106)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L32-50)
```text
    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
    }

    modifier onlyNotRegisteredToken(address _token) {
        require(registeredTokens[_token] == address(0), "allowed token");
        _;
    }

    modifier onlyLockedToken(address _token) {
        require(lockedTokens[_token], "unlocked token");
        _;
    }

    modifier onlyUnlockedToken(address _token) {
        require(!lockedTokens[_token], "locked token");
        _;
    }
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L73-92)
```text
    // deregisterToken can remove the token in registeredToken list.
    function deregisterToken(address _token)
        external
        onlyOwner
        onlyRegisteredToken(_token)
    {
        delete registeredTokens[_token];
        delete lockedTokens[_token];

        uint idx = indexOfTokens[_token];
        delete indexOfTokens[_token];

        if (idx < registeredTokenList.length-1) {
            registeredTokenList[idx] = registeredTokenList[registeredTokenList.length-1];
            indexOfTokens[registeredTokenList[idx]] = idx;
        }
        registeredTokenList.length--;

        emit TokenDeregistered(_token);
    }
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L94-104)
```text
    // lockToken can lock the token to prevent request token transferring.
    function lockToken(address _token)
        external
        onlyOwner
        onlyRegisteredToken(_token)
        onlyUnlockedToken(_token)
    {
        lockedTokens[_token] = true;

        emit TokenLocked(_token);
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
