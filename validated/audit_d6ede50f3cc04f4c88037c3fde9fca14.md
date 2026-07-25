### Title
Operator-Controlled `_tokenAddress` in `handleERC20Transfer` / `handleERC721Transfer` Not Validated Against Registered Token List — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`handleERC20Transfer` and `handleERC721Transfer` accept a fully caller-controlled `_tokenAddress` parameter with no check against the `registeredTokens` whitelist. Any registered bridge operator can supply an arbitrary token address to drain ERC20/ERC721 tokens held by the bridge (lock/unlock mode) or mint arbitrary amounts of any token for which the bridge holds minter role (mint/burn mode).

---

### Finding Description

The outbound deposit path `_requestERC20Transfer` enforces both `onlyRegisteredToken(_tokenAddress)` and `onlyUnlockedToken(_tokenAddress)` modifiers before touching any token:

```solidity
function _requestERC20Transfer(...)
    internal
    onlyRegisteredToken(_tokenAddress)   // ← enforced
    onlyUnlockedToken(_tokenAddress)     // ← enforced
``` [1](#0-0) 

The inbound settlement path `handleERC20Transfer`, callable by any registered operator, has **no such check**. It accepts `_tokenAddress` as a raw caller-supplied argument and immediately uses it to transfer or mint tokens:

```solidity
function handleERC20Transfer(
    bytes32 _requestTxHash,
    address _from,
    address _to,
    address _tokenAddress,   // ← no onlyRegisteredToken check
    uint256 _value,
    ...
)
    public
    onlyOperators            // ← only gate is operator membership
{
    ...
    if (modeMintBurn) {
        require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
    } else {
        IERC20(_tokenAddress).safeTransfer(_to, _value);
    }
}
``` [2](#0-1) 

The identical structural gap exists in `handleERC721Transfer`:

```solidity
function handleERC721Transfer(
    bytes32 _requestTxHash,
    address _from,
    address _to,
    address _tokenAddress,   // ← no onlyRegisteredToken check
    ...
)
    public
    onlyOperators
{
    ...
    if (modeMintBurn) {
        require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(...), ...);
    } else {
        IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
    }
}
``` [3](#0-2) 

The `registeredTokens` mapping and the `onlyRegisteredToken` modifier exist precisely to constrain which tokens the bridge is authorised to move: [4](#0-3) 

---

### Impact Explanation

**Lock/unlock mode (`modeMintBurn = false`):**  
The bridge holds real ERC20/ERC721 balances deposited by users. A malicious operator calls `handleERC20Transfer` with `_tokenAddress` set to any ERC20 token the bridge holds (registered or not, e.g. tokens accidentally sent to the bridge, or a second registered token), `_to` set to an attacker-controlled address, and `_value` set to the full balance. `safeTransfer` succeeds and the bridge is drained of that token.

**Mint/burn mode (`modeMintBurn = true`):**  
The bridge is typically granted minter role on the counterpart token. A malicious operator calls `handleERC20Transfer` with `_tokenAddress` set to any token for which the bridge holds minter role, minting an arbitrary `_value` to any `_to` address, inflating supply without a corresponding cross-chain deposit.

The corrupted value is the ERC20/ERC721 balance of the bridge contract (or the total supply of a mintable token), which is a system-managed bridged asset.

---

### Likelihood Explanation

Operators are semi-trusted relayers registered by the bridge owner — analogous to Sablier's envoys. The design intent (evidenced by the `onlyRegisteredToken` guard on the outbound path) is that operators should only be able to settle transfers for whitelisted tokens. A single compromised or malicious operator key is sufficient to trigger the drain; no owner collusion is required. Operator keys are hot keys used in automated relayer processes, making key compromise a realistic threat.

---

### Recommendation

Add `onlyRegisteredToken(_tokenAddress)` (and optionally `onlyUnlockedToken(_tokenAddress)`) to both `handleERC20Transfer` and `handleERC721Transfer`, mirroring the guards already present on the outbound path:

```solidity
function handleERC20Transfer(
    ...
    address _tokenAddress,
    ...
)
    public
    onlyOperators
    onlyRegisteredToken(_tokenAddress)   // add this
    onlyUnlockedToken(_tokenAddress)     // add this
{
``` [5](#0-4) 

Apply the same fix to `handleERC721Transfer` in `BridgeTransferERC721.sol`. [6](#0-5) 

---

### Proof of Concept

1. Deploy a bridge in lock/unlock mode (`modeMintBurn = false`) with TokenA registered and 1000 TokenA deposited.
2. Also send 500 TokenB (unregistered) to the bridge address directly.
3. Register attacker as an operator (or compromise an existing operator key).
4. Attacker calls:
   ```solidity
   bridge.handleERC20Transfer(
       bytes32(0),          // fake requestTxHash (or any unused hash)
       address(0),          // _from (irrelevant)
       attacker,            // _to
       address(tokenB),     // _tokenAddress — unregistered, no check performed
       500,                 // _value
       nextNonce,           // _requestedNonce
       0,                   // _requestedBlockNumber
       ""                   // _extraData
   );
   ```
5. The nonce/vote checks pass (single operator threshold = 1, or attacker controls quorum), `IERC20(tokenB).safeTransfer(attacker, 500)` executes, and 500 TokenB leave the bridge.
6. Repeat with `_tokenAddress = tokenA` to drain the registered token balance as well.

The same flow applies in mint/burn mode by substituting a token for which the bridge holds minter role, minting unbacked tokens to the attacker. [7](#0-6)

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

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L22-34)
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
```
