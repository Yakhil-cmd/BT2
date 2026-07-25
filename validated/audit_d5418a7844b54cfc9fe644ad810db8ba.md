### Title
Reentrancy in `requestERC20Transfer` / `onERC20Received` Allows Unauthorized Token Release on Counterpart Bridge — (File: `contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20` inherits no `ReentrancyGuard` and applies no `nonReentrant` modifier to `requestERC20Transfer`, `onERC20Received`, or `handleERC20Transfer`. The shared `requestNonce` counter is incremented at the very end of `_requestERC20Transfer`, after all external calls to the token contract. A registered ERC20 token with a transfer hook (e.g., ERC777 `tokensToSend`, or any custom `transferFrom` callback) can reenter the bridge before `requestNonce++` executes, emitting an extra `RequestValueTransfer` event under a distinct nonce. The counterpart bridge processes every distinct nonce independently, releasing bridged assets for each event — resulting in double-release for a single deposit.

---

### Finding Description

`BridgeTransferKLAY` explicitly inherits `ReentrancyGuard` and marks both `handleKLAYTransfer` and `_requestKLAYTransfer` with `nonReentrant`. `BridgeTransferERC20` does not inherit `ReentrancyGuard` at all and provides no equivalent protection. [1](#0-0) 

`_requestERC20Transfer` makes multiple external calls to the token contract before incrementing `requestNonce`:

1. `_payERC20FeeAndRefundChange` → `IERC20(_token).safeTransfer(feeReceiver, fee)` and `IERC20(_token).safeTransfer(from, feeRefund)`
2. `ERC20Burnable(_tokenAddress).burn(_value)` (mintBurn mode)

`requestNonce++` is the very last statement: [2](#0-1) 

`requestERC20Transfer` calls `safeTransferFrom` first — another external call — before entering `_requestERC20Transfer`: [3](#0-2) 

`onERC20Received` is a public entry point with no guard: [4](#0-3) 

The comment in `BridgeFee.sol` explicitly acknowledges that `_payKLAYFeeAndRefundChange` relies on the caller being `nonReentrant`, but no equivalent note or protection exists for the ERC20 path: [5](#0-4) 

---

### Impact Explanation

**Exact corrupted value**: `requestNonce` is consumed twice (nonces N and N+1) for a single token deposit of `_value`. The counterpart bridge processes both nonces independently, releasing `_value` tokens for each — a 2× unauthorized release of bridged assets.

**Affected asset**: Bridged ERC20 tokens on the counterpart chain (minted or unlocked by `handleERC20Transfer` on the parent bridge).

**Broken invariant**: Every `RequestValueTransfer` event must correspond to exactly one token deposit. Reentrancy breaks this 1:1 mapping, allowing the counterpart bridge to release tokens without a matching deposit.

---

### Likelihood Explanation

- **Trigger**: Any registered ERC20 token that executes a callback during `transferFrom` (ERC777 `tokensToSend` hook, or a custom hook). ERC777 tokens are backward-compatible with ERC20 and are commonly registered with bridges.
- **Privilege required**: The token must be registered by the bridge owner. However, ERC777 tokens are legitimate tokens; the bridge owner need not be malicious — they simply register a standards-compliant token.
- **Fee condition**: When `feeOfERC20 == 0` (the default), `_payERC20FeeAndRefundChange` makes no external calls and returns immediately, so the reentrant path through `onERC20Received` succeeds without any balance precondition on the bridge. [6](#0-5) 

---

### Recommendation

1. Add `ReentrancyGuard` inheritance to `BridgeTransferERC20` (mirroring `BridgeTransferKLAY`).
2. Apply `nonReentrant` to `requestERC20Transfer`, `onERC20Received`, and `handleERC20Transfer`.
3. Move `requestNonce++` before any external call (checks-effects-interactions pattern).

---

### Proof of Concept

```
Attacker deploys MaliciousERC20 with a transferFrom hook.
Bridge owner registers MaliciousERC20 (fee = 0).

Attacker calls:
  bridge.requestERC20Transfer(MaliciousERC20, victim, 100, 0, "")

Execution trace:
  1. bridge calls MaliciousERC20.safeTransferFrom(attacker, bridge, 100)
  2. MaliciousERC20.transferFrom hook fires → calls bridge.onERC20Received(attacker, victim, 100, 0, "")
  3. bridge._requestERC20Transfer(MaliciousERC20, attacker, victim, 100, 0, ""):
       requestNonce = N
       emit RequestValueTransfer(..., nonce=N, ...)   ← event 1
       requestNonce++ → N+1
  4. safeTransferFrom completes (100 tokens now in bridge)
  5. bridge._requestERC20Transfer(MaliciousERC20, attacker, victim, 100, 0, ""):
       requestNonce = N+1
       emit RequestValueTransfer(..., nonce=N+1, ...) ← event 2
       requestNonce++ → N+2

Counterpart bridge operators call handleERC20Transfer for nonce N  → releases 100 tokens to victim
Counterpart bridge operators call handleERC20Transfer for nonce N+1 → releases 100 tokens to victim

Result: 200 tokens released on counterpart chain for 100 tokens deposited.
``` [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L20-23)
```text
import "../../libs/openzeppelin-contracts-v2/contracts/utils/ReentrancyGuard.sol";


contract BridgeTransferKLAY is BridgeTransfer, ReentrancyGuard {
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L71-73)
```text
        public
        onlyOperators
        nonReentrant
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L28-73)
```text
contract BridgeTransferERC20 is BridgeTokens, IERC20BridgeReceiver, BridgeTransfer {
    using SafeERC20 for IERC20;

    // handleERC20Transfer sends the token by the request.
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-108)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
        require(_value > 0, "zero ERC20 token amount");

        uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);

        if (modeMintBurn) {
            ERC20Burnable(_tokenAddress).burn(_value);
        }

        emit RequestValueTransfer(
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            requestNonce,
            fee,
            _extraData
        );
        requestNonce++;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L111-121)
```text
    function onERC20Received(
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        public
    {
        _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L124-135)
```text
    function requestERC20Transfer(
        address _tokenAddress,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        public
    {
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
        _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L41-43)
```text
    // Caller of this function must be nonReentrant.
    // - BridgeTransferKLAY._requestKLAYTransfer() is nonReentrant
    function _payKLAYFeeAndRefundChange(uint256 _feeLimit) internal returns(uint256) {
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L68-88)
```text
    function _payERC20FeeAndRefundChange(address from, address _token, uint256 _feeLimit) internal returns(uint256) {
        uint256 fee = feeOfERC20[_token];

        if (feeReceiver != address(0) && fee > 0) {
            require(_feeLimit >= fee, "insufficient feeLimit");

            IERC20(_token).safeTransfer(feeReceiver, fee);

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                IERC20(_token).safeTransfer(from, feeRefund);
            }

            return fee;
        }

        if (_feeLimit > 0) {
            IERC20(_token).safeTransfer(from, _feeLimit);
        }
        return 0;
    }
```
