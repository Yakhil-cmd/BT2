### Title
Missing `onlyRegisteredToken` Validation in `handleERC20Transfer` / `handleERC721Transfer` Allows Operators to Drain Arbitrary Bridge-Held Tokens — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

`handleERC20Transfer` and `handleERC721Transfer` accept a caller-supplied `_tokenAddress` without validating it against the registered-token whitelist. The outbound path (`_requestERC20Transfer`) enforces `onlyRegisteredToken(_tokenAddress)`, but the inbound handle path does not. A malicious operator (or colluding operators at threshold) can supply any token address the bridge holds, causing the bridge to call `safeTransfer` or `mint` on an arbitrary contract and drain bridge-held assets.

---

### Finding Description

`_requestERC20Transfer` (the outbound deposit path) is guarded by two modifiers:

```solidity
// BridgeTransferERC20.sol L85-86
internal
onlyRegisteredToken(_tokenAddress)
onlyUnlockedToken(_tokenAddress)
```

`handleERC20Transfer` (the inbound settlement path) has neither guard:

```solidity
// BridgeTransferERC20.sol L42-43
public
onlyOperators
```

After passing the nonce check and multi-sig vote, the function unconditionally executes:

```solidity
// BridgeTransferERC20.sol L68-72
if (modeMintBurn) {
    require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
} else {
    IERC20(_tokenAddress).safeTransfer(_to, _value);
}
```

`_tokenAddress` is entirely operator-controlled. The vote key is `keccak256(msg.data)` (BridgeOperator.sol L109), so each unique `(tokenAddress, to, value, nonce)` tuple is a fresh vote. The default operator threshold is **1** (BridgeOperator.sol L56-57), meaning a single operator can unilaterally execute the call. Even at threshold > 1, colluding operators can do the same.

The same pattern exists in `handleERC721Transfer` (BridgeTransferERC721.sol L29-71), which calls `IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId)` or `ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(...)` on an unvalidated address.

---

### Impact Explanation

**Non-mintBurn mode (lock/unlock):** The bridge holds deposited ERC20/ERC721 tokens. A malicious operator fabricates a fresh `_requestTxHash` (any unused `bytes32`) and a fresh `_requestedNonce` (≥ `lowerHandleNonce`), sets `_tokenAddress` to any token the bridge holds, and `_to` to their own address. The bridge executes `safeTransfer(attacker, balance)`, draining the entire token holding. This affects all registered tokens simultaneously — the attacker can loop over every token the bridge holds.

**MintBurn mode:** The operator supplies a malicious contract address implementing `mint(address, uint256)`. The bridge calls into it with no further validation, enabling arbitrary side effects.

The corrupted value is the bridge's ERC20/ERC721 token balance: it is reduced to zero without a corresponding legitimate cross-chain request, breaking the 1:1 asset-backing invariant that the bridge is designed to maintain.

---

### Likelihood Explanation

- Default operator threshold is 1 (BridgeOperator.sol L56-57); a single operator can execute this without any collusion.
- The operator role is semi-trusted (registered by owner, but a separate key/entity), directly analogous to the Sablier "team member with separation of duty" scenario.
- No on-chain guard prevents a fresh nonce + fabricated tx hash from passing `_lowerHandleNonceCheck` and `_setHandledRequestTxHash`.
- The `closedValueTransferVotes` map only prevents replay of the *same* nonce, not fabrication of a new one.

---

### Recommendation

Add `onlyRegisteredToken(_tokenAddress)` (and `onlyUnlockedToken(_tokenAddress)`) to both `handleERC20Transfer` and `handleERC721Transfer`, mirroring the guards already present on the outbound path:

```solidity
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
    onlyRegisteredToken(_tokenAddress)   // ADD
    onlyUnlockedToken(_tokenAddress)     // ADD
{
    ...
}
```

Apply the same fix to `handleERC721Transfer`. This ensures the inbound settlement path is constrained to the same token whitelist as the outbound deposit path.

---

### Proof of Concept

Setup: Bridge deployed in non-mintBurn mode, threshold = 1 (default). Token A registered and deposited (bridge holds 1000 A). Attacker is a registered operator.

```solidity
// Attacker calls:
bridge.handleERC20Transfer(
    bytes32(uint256(0xdeadbeef)),  // fabricated, unused tx hash
    address(0),                    // _from (irrelevant)
    attacker,                      // _to = attacker
    address(tokenA),               // _tokenAddress = any token bridge holds
    1000e18,                       // _value = full bridge balance
    bridge.upperHandleNonce() + 1, // fresh nonce >= lowerHandleNonce
    block.number,
    ""
);
// Result: bridge calls tokenA.safeTransfer(attacker, 1000e18)
// Bridge balance of tokenA: 0. Attacker balance: 1000e18.
```

The `_voteValueTransfer` call succeeds because `voteCounts[keccak256(msg.data)] >= threshold (1)` after the single operator vote. `_lowerHandleNonceCheck` passes because the fresh nonce ≥ `lowerHandleNonce`. `_setHandledRequestTxHash` records the fabricated hash. The bridge then transfers all of its token A holdings to the attacker. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-86)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L103-116)
```text
    function _voteValueTransfer(uint64 _requestNonce)
        internal
        returns(bool)
    {
        require(!closedValueTransferVotes[_requestNonce], "closed vote");

        bytes32 voteKey = keccak256(msg.data);
        if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
            closedValueTransferVotes[_requestNonce] = true;
            return true;
        }

        return false;
    }
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L32-35)
```text
    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
    }
```

**File:** contracts/service_chain/bridge/BridgeHandledRequests.sol (L23-25)
```text
    function _setHandledRequestTxHash(bytes32 _requestTxHash) internal {
        handledRequestTx[_requestTxHash] = true;
    }
```
