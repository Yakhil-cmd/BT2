### Title
Missing `onlyRegisteredToken` Validation in `handleERC20Transfer` and `handleERC721Transfer` Allows Operators to Mint or Drain Arbitrary Tokens — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The Kaia service-chain bridge's inbound handle functions (`handleERC20Transfer`, `handleERC721Transfer`) accept a caller-supplied `_tokenAddress` and immediately use it to mint or transfer tokens, without checking whether that address is present in the `registeredTokens` configuration mapping. The outbound request path enforces `onlyRegisteredToken`, but the inbound handle path does not. This is the direct Kaia analog of the Connext/Nomad "configuration is crucial" class: the `registeredTokens` mapping is the critical protected state, and it is not enforced on the handle side.

---

### Finding Description

`BridgeTokens.sol` defines the `registeredTokens` mapping and the `onlyRegisteredToken` modifier: [1](#0-0) 

The outbound request path correctly enforces this modifier: [2](#0-1) 

However, the inbound handle path does **not** apply `onlyRegisteredToken` to `_tokenAddress`: [3](#0-2) 

After passing only `onlyOperators` and nonce checks, the function unconditionally calls:

```solidity
ERC20Mintable(_tokenAddress).mint(_to, _value)   // modeMintBurn=true
IERC20(_tokenAddress).safeTransfer(_to, _value)  // modeMintBurn=false
```

The same omission exists in `handleERC721Transfer`: [4](#0-3) 

The `BridgeOperator` constructor sets the default `operatorThresholds[ValueTransfer]` to **1**: [5](#0-4) 

So with the default threshold, a single operator can execute `handleERC20Transfer` or `handleERC721Transfer` with any arbitrary `_tokenAddress`.

---

### Impact Explanation

- **`modeMintBurn = true`**: An operator supplies an arbitrary ERC20/ERC721 address that has granted the bridge contract minter role. The bridge calls `.mint(_to, _value)` on that address, creating tokens out of thin air for any recipient. This is an **unauthorized mint** of bridged assets.
- **`modeMintBurn = false`**: An operator supplies any ERC20 address for which the bridge holds a balance (e.g., tokens deposited by users). The bridge calls `.safeTransfer(_to, _value)`, draining those tokens to an arbitrary recipient. This is an **unauthorized transfer** of bridged assets.

The corrupted value is the token balance of `_to` (inflated) and the bridge contract (drained), both of which are protected asset states.

---

### Likelihood Explanation

- The default `operatorThresholds[ValueTransfer]` is 1, so a single compromised or malicious operator is sufficient.
- Operators are registered by the bridge owner, making them semi-trusted — not fully privileged. A compromised operator key (e.g., via key theft) is a realistic attack vector within the production attack surface.
- The `_voteValueTransfer` mechanism uses `keccak256(msg.data)` as the vote key, so with threshold=1 no collusion is needed at all. [6](#0-5) 

---

### Recommendation

Add the `onlyRegisteredToken(_tokenAddress)` modifier to both `handleERC20Transfer` and `handleERC721Transfer`, mirroring the protection already present on the outbound request path:

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
    onlyRegisteredToken(_tokenAddress)   // ADD THIS
{
    ...
}
```

Apply the same fix to `handleERC721Transfer`. This ensures the `registeredTokens` configuration is enforced symmetrically on both the outbound and inbound bridge paths.

---

### Proof of Concept

1. Deploy `Bridge` in `modeMintBurn = true`.
2. Deploy a legitimate `ServiceChainToken` and register it: `bridge.registerToken(token, cToken)`.
3. Deploy a second, unregistered `MaliciousToken` and grant the bridge minter role on it.
4. As the single operator (threshold=1), call:
   ```solidity
   bridge.handleERC20Transfer(
       txHash, attacker, attacker,
       maliciousToken,   // NOT in registeredTokens
       1_000_000e18,     // arbitrary large amount
       0, 0, ""
   );
   ```
5. The bridge calls `MaliciousToken.mint(attacker, 1_000_000e18)` — succeeds with no revert.
6. Attacker now holds 1,000,000 tokens minted without any corresponding cross-chain deposit.

The same flow applies in `modeMintBurn = false` by substituting any ERC20 token for which the bridge holds a balance, draining it to the attacker. [7](#0-6) [8](#0-7)

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

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L57-71)
```text
    function registerToken(address _token, address _cToken)
        external
        onlyOwner
        onlyNotRegisteredToken(_token)
    {
        // If _cToken == 0 then registeredTokens[_token] = 0, which confuses the
        // onlyRegisteredToken and onlyNotRegisteredToken modifiers.
        require(_cToken != address(0), "counterpart token address is zero");

        registeredTokens[_token] = _cToken;
        indexOfTokens[_token] = registeredTokenList.length;
        registeredTokenList.push(_token);

        emit TokenRegistered(_token);
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-86)
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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L54-57)
```text
    constructor() internal {
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L102-116)
```text
    // _voteValueTransfer votes value transfer transaction with the operator.
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
