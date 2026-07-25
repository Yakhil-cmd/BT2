### Title
Bridge `onERC20Received` Accepts Unverified Caller-Supplied `_from`, Enabling Fee-Refund Theft by Any Registered Token Contract — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

The Kaia service-chain bridge's 1-step ERC-20 deposit callback `onERC20Received` is a `public` function that accepts a caller-supplied `_from` address with no verification that it matches the actual depositor. The bridge then uses `_from` as the destination for ERC-20 fee refunds. Any contract that is registered as a bridge token can call `onERC20Received` directly with an arbitrary `_from`, redirecting the fee-change refund to any address while the bridge's token balance is consumed.

---

### Finding Description

**1-step deposit flow (legitimate)**

`ERC20ServiceChain.requestValueTransfer` transfers `amount + feeLimit` to the bridge and then calls:

```solidity
// contracts/testing/sc_erc20/ERC20ServiceChain.sol:46
IERC20BridgeReceiver(bridge).onERC20Received(msg.sender, _to, _amount, _feeLimit, _extraData);
```

`msg.sender` here is the actual user, so `_from` is correct. [1](#0-0) 

**The vulnerable callback**

```solidity
// contracts/service_chain/bridge/BridgeTransferERC20.sol:111-121
function onERC20Received(
    address _from,      // ← fully caller-controlled, never verified
    address _to,
    uint256 _value,
    uint256 _feeLimit,
    bytes memory _extraData
)
    public              // ← no access control here
{
    _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
}
``` [2](#0-1) 

The only guard is `onlyRegisteredToken(msg.sender)` inside `_requestERC20Transfer`, which checks that the *calling contract* is a registered token — it says nothing about whether `_from` is the real depositor. [3](#0-2) 

**Fee refund is paid to `_from`**

Inside `_requestERC20Transfer`, the bridge calls:

```solidity
uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);
```

And `_payERC20FeeAndRefundChange` unconditionally transfers the fee change back to `from`:

```solidity
// contracts/service_chain/bridge/BridgeFee.sol:77-79
if (feeRefund > 0) {
    IERC20(_token).safeTransfer(from, feeRefund);   // ← goes to spoofed address
}
// ...
if (_feeLimit > 0) {
    IERC20(_token).safeTransfer(from, _feeLimit);   // ← entire feeLimit if no fee set
}
``` [4](#0-3) 

**Same flaw in ERC-721 path**

`onERC721Received` is identically structured — `public`, no access control, `_from` is caller-supplied and passed straight to `_requestERC721Transfer`. [5](#0-4) 

The `IERC721BridgeReceiver` interface omits the `operator` field that the standard ERC-721 `onERC721Received` requires, making it structurally impossible for the bridge to authenticate the initiator — the exact design gap flagged in the Astaria report. [6](#0-5) 

---

### Impact Explanation

A registered token contract (or any contract whose address has been added to the bridge's token registry) can:

1. Transfer `amount + feeLimit` tokens to the bridge (legitimate deposit).
2. Call `bridge.onERC20Received(victim, attacker_to, amount, feeLimit, extraData)` with `_from = victim`.
3. The bridge passes `onlyRegisteredToken(msg.sender)` because the caller is registered.
4. `_payERC20FeeAndRefundChange(victim, token, feeLimit)` executes and sends `feeRefund` (or the entire `feeLimit` when no fee is configured) to `victim` — an address that did not deposit anything.
5. In `modeMintBurn`, the bridge also burns `amount` tokens from its own balance and emits `RequestValueTransfer(from=victim, to=attacker_to, ...)`, causing the counterpart bridge operators to mint tokens to `attacker_to`.

Corrupted values:
- **ERC-20 token balance of bridge**: reduced by `feeRefund` sent to wrong address.
- **`RequestValueTransfer` event `from` field**: spoofed, causing counterpart-chain operators to attribute the cross-chain mint to an innocent address.

---

### Likelihood Explanation

The trigger requires `msg.sender` to be a registered token contract. Token registration is performed by the bridge owner (`onlyOwner`), so a fully external attacker cannot register an arbitrary contract. However:

- A legitimate token contract that is later upgraded or that contains a re-entrant or delegated-call path could be weaponised.
- The `onERC20Received` interface is documented as a public hook for "1-step deposits"; any third-party token that implements `ERC20ServiceChain` and exposes a function allowing a caller to supply `_from` freely (e.g., a wrapper or router) becomes an attack vector without any bridge-owner action.
- The absence of the `operator` field in the interface (`IERC20BridgeReceiver`, `IERC721BridgeReceiver`) means the bridge structurally cannot add this check later without a breaking interface change.

Likelihood: **Low-Medium** (semi-trusted registered token contract required; no majority-validator collusion needed).

---

### Recommendation

1. **Add `msg.sender` verification inside `onERC20Received`**: require that `_from` equals `msg.sender` (i.e., the token contract itself is the depositor), or drop `_from` from the callback and derive it from `msg.sender` on the bridge side.

2. **Alternatively, follow the ERC-721 standard pattern**: add an `operator` parameter to both `IERC20BridgeReceiver.onERC20Received` and `IERC721BridgeReceiver.onERC721Received` so the bridge can verify the initiator, mirroring `IERC721Receiver.onERC721Received(address operator, address from, ...)`.

3. **Short-term mitigation**: add `require(msg.sender == _from || isRegisteredToken(msg.sender), "invalid from")` inside `onERC20Received` to reject spoofed `_from` values from registered token contracts.

---

### Proof of Concept

```
Setup:
  - Bridge deployed in lock mode, feeOfERC20[token] = 0 (no fee configured)
  - MaliciousToken registered by bridge owner
  - Bridge holds 1000 token (from prior legitimate deposits)

Attack:
  1. MaliciousToken.attack(victim, 100):
       a. MaliciousToken.transfer(bridge, 100)          // bridge balance: 1100
       b. bridge.onERC20Received(victim, attacker, 100, 100, "")
            → _requestERC20Transfer(MaliciousToken, victim, attacker, 100, 100, "")
            → onlyRegisteredToken(MaliciousToken) passes
            → _payERC20FeeAndRefundChange(victim, MaliciousToken, 100)
                 → feeOfERC20[MaliciousToken] == 0
                 → safeTransfer(victim, 100)            // 100 tokens sent to victim (wrong address)
            → emit RequestValueTransfer(from=victim, to=attacker, value=100)
                 → counterpart bridge operators mint 100 tokens to attacker

Result:
  - victim receives 100 tokens they did not deposit (bridge balance drained by 100)
  - attacker receives 100 tokens minted on counterpart chain
  - actual depositor (MaliciousToken contract) loses nothing (it deposited 100 and the bridge
    sent 100 to victim, net: bridge drained by 100 from prior legitimate deposits)
```

Corrupted state: `bridge.balanceOf -= 100` (unauthorized transfer to `victim`); `RequestValueTransfer.from` = spoofed `victim`; counterpart chain mints 100 tokens to `attacker` without a legitimate deposit from `victim`.

### Citations

**File:** contracts/testing/sc_erc20/ERC20ServiceChain.sol (L44-47)
```text
    function requestValueTransfer(uint256 _amount, address _to, uint256 _feeLimit, bytes calldata _extraData) external {
        require(transfer(bridge, _amount.add(_feeLimit)), "requestValueTransfer: transfer failed");
        IERC20BridgeReceiver(bridge).onERC20Received(msg.sender, _to, _amount, _feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-91)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
        require(_value > 0, "zero ERC20 token amount");

        uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L108-118)
```text
    // onERC721Received function of ERC721 token for 1-step deposits to the Bridge
    function onERC721Received(
        address _from,
        uint256 _tokenId,
        address _to,
        bytes memory _extraData
    )
        public
    {
        _requestERC721Transfer(msg.sender, _from, _to, _tokenId, _extraData);
    }
```

**File:** contracts/service_chain/IERC721BridgeReceiver.sol (L19-21)
```text
contract IERC721BridgeReceiver {
    function onERC721Received(address _from, uint256 _tokenId, address _to, bytes memory _extraData) public;
}
```
