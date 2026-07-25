### Title
Unchecked `IERC721.transferFrom` in Bridge Allows Silent Failure, Consuming Bridge Nonce Without Asset Delivery — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721` calls `IERC721(_tokenAddress).transferFrom(...)` in two places without any success check or safe-transfer wrapper. Unlike `BridgeTransferERC20`, which correctly uses `SafeERC20.safeTransfer`/`safeTransferFrom`, the ERC721 bridge path has no equivalent protection. For non-standard ERC721 tokens that silently return without reverting on failure, this causes two distinct protected-state impacts: (1) a deposit-side unauthorized cross-chain mint/release triggered by a transfer that never actually moved the token, and (2) a withdrawal-side permanent nonce consumption that leaves the recipient without their NFT.

---

### Finding Description

`BridgeTransferERC20` imports and applies `SafeERC20`:

```solidity
// BridgeTransferERC20.sol line 22-29
import "../../libs/openzeppelin-contracts-v2/contracts/token/ERC20/SafeERC20.sol";
...
using SafeERC20 for IERC20;
```

and uses `safeTransfer`/`safeTransferFrom` everywhere:

```solidity
IERC20(_tokenAddress).safeTransfer(_to, _value);          // line 71
IERC20(_tokenAddress).safeTransferFrom(msg.sender, ...);  // line 133
```

`BridgeTransferERC721` imports no safe-transfer library and makes two raw calls:

**Deposit path (`requestERC721Transfer`, line 129):**
```solidity
IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
_requestERC721Transfer(_tokenAddress, msg.sender, _to, _tokenId, _extraData);
```

**Withdrawal path (`handleERC721Transfer`, line 69):**
```solidity
// State already mutated above (lines 49-64):
_setHandledRequestTxHash(_requestTxHash);          // nonce marked handled
handleNoncesToBlockNums[_requestedNonce] = ...;    // nonce→block recorded
_updateHandleNonce(_requestedNonce);               // lowerHandleNonce advanced
emit HandleValueTransfer(...);                     // event emitted

// Then the actual transfer — unchecked:
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
```

The `IERC721` interface declares `transferFrom` as returning `void`:

```solidity
function transferFrom(address from, address to, uint256 tokenId) public;
```

A non-standard ERC721 token that implements `transferFrom` to silently return (without reverting and without moving the token) will not be caught by Solidity's ABI decoder, because no return value is expected. The call succeeds from the bridge's perspective.

---

### Impact Explanation

**Deposit path — unauthorized cross-chain mint/release:**

1. Attacker registers a non-standard ERC721 token on the bridge (or uses one already registered).
2. Attacker calls `requestERC721Transfer`. The `transferFrom` silently fails; the token stays with the attacker.
3. `_requestERC721Transfer` executes: `requestNonce++` and `RequestValueTransferEncoded` is emitted.
4. Counterpart bridge operators observe the event and call `handleERC721Transfer` on the counterpart chain.
   - In `modeMintBurn` mode: `ERC721MetadataMintable.mintWithTokenURI` mints a new NFT to the recipient — **unauthorized mint of a bridged asset**.
   - In lock/unlock mode: the counterpart bridge transfers an NFT from its own custody to the recipient — **unauthorized transfer of bridge-held assets**.

The attacker retains the original NFT and receives (or causes a recipient to receive) a counterpart NFT for free.

**Withdrawal path — permanent nonce consumption without delivery:**

1. A legitimate cross-chain withdrawal reaches quorum; operators call `handleERC721Transfer`.
2. Lines 49–64 execute: the request tx hash is marked handled, `handleNoncesToBlockNums` is written, `_updateHandleNonce` advances `lowerHandleNonce`.
3. `IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId)` silently fails.
4. The nonce is permanently consumed (`closedValueTransferVotes[nonce] = true`, `lowerHandleNonce` advanced past it). The request cannot be replayed.
5. The recipient never receives their NFT — **permanent loss of a bridged asset**.

---

### Likelihood Explanation

Likelihood is **Low**. The bridge operator set must register the token, and the token must be non-standard (silently non-reverting on failed `transferFrom`). However, the bridge's `registerToken` is callable by the owner without any on-chain validation of the token's compliance, and non-reverting ERC721 implementations exist in the wild. The deposit-path variant is directly attacker-triggerable once a vulnerable token is registered.

---

### Recommendation

Mirror the ERC20 bridge pattern. Add a safe-transfer helper for ERC721 (there is no standard `SafeERC721` in OpenZeppelin v2, but one can be implemented inline):

```solidity
function _safeTransferFromERC721(address token, address from, address to, uint256 tokenId) internal {
    (bool success, bytes memory data) = token.call(
        abi.encodeWithSelector(IERC721(token).transferFrom.selector, from, to, tokenId)
    );
    require(success && (data.length == 0 || abi.decode(data, (bool))), "ERC721 transferFrom failed");
}
```

Replace both raw calls:

```solidity
// handleERC721Transfer (line 69)
_safeTransferFromERC721(_tokenAddress, address(this), _to, _tokenId);

// requestERC721Transfer (line 129)
_safeTransferFromERC721(_tokenAddress, msg.sender, address(this), _tokenId);
```

Additionally, in `handleERC721Transfer`, move the state-mutation block (lines 49–64) **after** the transfer call, so that a failed transfer rolls back the nonce update atomically.

---

### Proof of Concept

```solidity
// Malicious non-standard ERC721 — silently does nothing on transferFrom
contract SilentERC721 is IERC721 {
    mapping(uint256 => address) public owners;
    function mint(address to, uint256 id) external { owners[id] = to; }
    function ownerOf(uint256 id) public view returns (address) { return owners[id]; }
    // transferFrom does NOT revert and does NOT move the token
    function transferFrom(address, address, uint256) public { /* silent no-op */ }
    // ... other IERC721 stubs
}

// Attack sequence (deposit path):
// 1. Deploy SilentERC721, mint tokenId=1 to attacker
// 2. Owner registers SilentERC721 on bridge
// 3. Attacker calls bridge.requestERC721Transfer(silentERC721, recipient, 1, "")
//    -> transferFrom silently fails, attacker still owns tokenId=1
//    -> RequestValueTransferEncoded event emitted with requestNonce=0
// 4. Counterpart bridge operators call handleERC721Transfer (modeMintBurn=true)
//    -> mintWithTokenURI(recipient, 1, ...) succeeds
//    -> Recipient receives a minted NFT; attacker still holds the original
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L43-64)
```text
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L120-131)
```text
    // requestERC721Transfer requests transfer ERC721 to _to on relative chain.
    function requestERC721Transfer(
        address _tokenAddress,
        address _to,
        uint256 _tokenId,
        bytes memory _extraData
    )
        public
    {
        IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
        _requestERC721Transfer(_tokenAddress, msg.sender, _to, _tokenId, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L28-29)
```text
contract BridgeTransferERC20 is BridgeTokens, IERC20BridgeReceiver, BridgeTransfer {
    using SafeERC20 for IERC20;
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L132-134)
```text
    {
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
        _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/IERC721.sol (L44-44)
```text
    function transferFrom(address from, address to, uint256 tokenId) public;
```
