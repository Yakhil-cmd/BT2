### Title
Bridge `handleERC20Transfer` and `handleERC721Transfer` Accept Arbitrary Unregistered Token Addresses — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`handleERC20Transfer` and `handleERC721Transfer` — the operator-callable functions that settle incoming cross-chain value transfers on the destination bridge — accept a caller-supplied `_tokenAddress` without validating it against the `registeredTokens` whitelist. The outgoing path (`_requestERC20Transfer` / `_requestERC721Transfer`) correctly enforces `onlyRegisteredToken`, but the incoming settlement path does not. A bridge operator meeting the (default: 1-of-N) threshold can therefore settle a transfer for any arbitrary ERC20/ERC721 contract, bypassing the token whitelist entirely.

---

### Finding Description

`BridgeTokens` maintains a `registeredTokens` mapping and exposes the `onlyRegisteredToken` modifier to enforce that only approved tokens may be bridged. [1](#0-0) 

The outgoing request functions correctly apply this guard: [2](#0-1) [3](#0-2) 

The incoming settlement functions do **not**: [4](#0-3) [5](#0-4) 

`handleERC20Transfer` carries only `onlyOperators`. The `_tokenAddress` argument flows directly into either `ERC20Mintable(_tokenAddress).mint(_to, _value)` (mint-burn mode) or `IERC20(_tokenAddress).safeTransfer(_to, _value)` (lock-unlock mode) with no whitelist check.

The operator threshold defaults to **1** at construction: [6](#0-5) 

A single operator is therefore sufficient to unilaterally execute the settlement (no multi-sig quorum required at default configuration).

---

### Impact Explanation

**Mint-burn mode (child-chain bridge, `modeMintBurn = true`):** An operator calls `handleERC20Transfer` with an arbitrary `_tokenAddress` for which the bridge holds the `MinterRole`. The bridge mints `_value` tokens to `_to` on a contract that was never registered as a bridgeable asset. This constitutes an unauthorized mint of bridged assets.

**Lock-unlock mode (parent-chain bridge, `modeMintBurn = false`):** An operator calls `handleERC20Transfer` with any ERC20 token address whose balance the bridge holds (e.g., tokens deposited by users or accumulated fees). The bridge transfers `_value` of that token to an arbitrary `_to`, draining bridge-managed funds without a corresponding legitimate cross-chain request.

The same logic applies to `handleERC721Transfer` for NFTs.

The corrupted value is: the ERC20/ERC721 balance of `_to` (inflated by unauthorized mint or transfer) and the bridge contract's token balance (drained in lock-unlock mode).

---

### Likelihood Explanation

The default operator threshold is 1, so no collusion is required — a single compromised or malicious operator suffices. The bridge operator role is distinct from the owner role and is intended to be held by automated relayer nodes, which are a realistic compromise target. The asymmetry between the outgoing and incoming paths is a code-level omission, not a documented design choice, making accidental or intentional exploitation straightforward once an operator key is obtained.

---

### Recommendation

Add `onlyRegisteredToken(_tokenAddress)` and `onlyUnlockedToken(_tokenAddress)` modifiers to both `handleERC20Transfer` and `handleERC721Transfer`, mirroring the guards already present on the outgoing request functions:

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

Apply the same fix to `handleERC721Transfer`.

---

### Proof of Concept

```solidity
// Assume:
// - bridge deployed with modeMintBurn = true (child chain)
// - bridge has MinterRole on tokenA (registered) and tokenB (NOT registered)
// - operator threshold = 1 (default)
// - attacker controls one operator key

// Step 1: attacker calls handleERC20Transfer with unregistered tokenB
bridge.handleERC20Transfer(
    bytes32(0),          // fake requestTxHash
    address(0),          // from (irrelevant)
    attacker,            // to: attacker receives minted tokens
    address(tokenB),     // _tokenAddress: NOT in registeredTokens
    1_000_000e18,        // _value: arbitrary large amount
    999,                 // _requestedNonce: any unused nonce
    1,                   // _requestedBlockNumber
    ""
);
// Result: tokenB.mint(attacker, 1_000_000e18) executes successfully.
// No revert because handleERC20Transfer has no onlyRegisteredToken check.
// registeredTokens[tokenB] == address(0) would have blocked this on the request side.
```

The `_voteValueTransfer` call inside `handleERC20Transfer` returns `true` immediately when the threshold is 1 and the operator is the sole voter, so the mint executes in the same transaction. [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L22-35)
```text
    mapping(address => address) public registeredTokens; // <token, counterpart token>
    mapping(address => uint) public indexOfTokens; // <token, index>
    address[] public registeredTokenList;
    mapping(address => bool) public lockedTokens;

    event TokenRegistered(address indexed token);
    event TokenDeregistered(address indexed token);
    event TokenLocked(address indexed token);
    event TokenUnlocked(address indexed token);

    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-87)
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L73-84)
```text
    // _requestERC721Transfer requests transfer ERC721 to _to on relative chain.
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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L96-99)
```text
        if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
            return true;
        }
        return false;
```
