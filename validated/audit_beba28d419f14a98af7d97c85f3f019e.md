The code is clear enough to render a verdict. Let me confirm the exact check in the extension versus what the pool passes.

The vulnerability is confirmed. Here is the complete trace:

**Call chain:**
1. `callerAddr` (non-allowlisted) calls `pool.addLiquidity(owner=allowlistedAddr, ...)`
2. Pool calls `_beforeAddLiquidity(msg.sender=callerAddr, owner=allowlistedAddr, ...)` [1](#0-0) 
3. `_beforeAddLiquidity` encodes and forwards both `sender` and `owner` to the extension [2](#0-1) 
4. Extension's `beforeAddLiquidity` receives `sender=callerAddr` as its **first unnamed/ignored parameter** and `owner=allowlistedAddr` as its second [3](#0-2) 
5. The guard checks `allowedDepositor[msg.sender/*pool*/][owner/*allowlistedAddr*/]` → `true` → **passes** [4](#0-3) 

The `sender` argument (the actual unprivileged caller) is silently discarded. The allowlist is checked against `owner` — the position recipient — not the depositing address.

---

### Title
`DepositAllowlistExtension` checks `owner` instead of `sender`, allowing any unprivileged caller to bypass the deposit allowlist — (`metric-periphery/contracts/extensions/DepositAllowlistExtension.sol`)

### Summary
`DepositAllowlistExtension.beforeAddLiquidity` ignores the `sender` argument (the actual `msg.sender` of the `addLiquidity` call) and instead validates the `owner` argument (the position recipient). Because `pool.addLiquidity` accepts an arbitrary `owner` address from any caller, a non-allowlisted address can pass the guard by supplying any allowlisted address as `owner`.

### Finding Description
`MetricOmmPool.addLiquidity` is a public function with no caller restriction of its own. It passes both `msg.sender` (as `sender`) and the caller-supplied `owner` to `_beforeAddLiquidity`, which forwards both to the extension. [5](#0-4) 

`DepositAllowlistExtension.beforeAddLiquidity` declares the first parameter (`sender`) as an unnamed, unused slot and evaluates only `owner`:

```solidity
function beforeAddLiquidity(address, address owner, uint80, LiquidityDelta calldata, bytes calldata)
    external view override returns (bytes4)
{
    if (!allowAllDepositors[msg.sender] && !allowedDepositor[msg.sender][owner]) {
        revert IMetricOmmPoolActions.NotAllowedToDeposit();
    }
    ...
}
``` [6](#0-5) 

The contract's own NatSpec states it "Gates `addLiquidity` by depositor address" and the admin-facing API is named `setAllowedToDeposit` / `isAllowedToDeposit`, making clear the intent is to restrict the **depositing caller**, not the position recipient. The implementation inverts this: it restricts the recipient while leaving the caller unchecked.

### Impact Explanation
Any address — regardless of allowlist status — can add liquidity to a pool protected by `DepositAllowlistExtension` by passing any allowlisted address as `owner`. The attacker's tokens fund the position (pulled via the modify-liquidity callback from `msg.sender`), and the position is credited to the allowlisted `owner`. The attacker gains no direct financial return, but the allowlist restriction — the pool admin's primary access-control mechanism for deposits — is completely nullified. An attacker can:

- Inject liquidity into arbitrary bins, shifting the pool cursor or bin composition without authorization.
- Front-run or sandwich other depositors by manipulating bin state before their transactions.
- Grief the pool or the allowlisted owner by creating unwanted LP positions on their behalf.

This constitutes broken core pool functionality: the allowlist extension provides zero protection against unauthorized deposits.

### Likelihood Explanation
The attack requires only knowledge of one allowlisted address (readable from `AllowedToDepositSet` events or `allowedDepositor` view) and the ability to call `pool.addLiquidity` directly. No privileged role, special token, or off-chain data is needed. The pool's `addLiquidity` is fully public with no caller restriction. [7](#0-6) 

### Recommendation
Replace the ignored first parameter with `sender` and validate it instead of (or in addition to) `owner`:

```solidity
function beforeAddLiquidity(address sender, address, uint80, LiquidityDelta calldata, bytes calldata)
    external view override returns (bytes4)
{
    if (!allowAllDepositors[msg.sender] && !allowedDepositor[msg.sender][sender]) {
        revert IMetricOmmPoolActions.NotAllowedToDeposit();
    }
    return IMetricOmmExtensions.beforeAddLiquidity.selector;
}
```

If the intent is to restrict both who can call and who can receive positions, both `sender` and `owner` should be checked.

### Proof of Concept

```solidity
// Setup
DepositAllowlistExtension ext = new DepositAllowlistExtension(factory);
// pool admin allowlists ownerAddr, NOT callerAddr
ext.setAllowedToDeposit(address(pool), ownerAddr, true);

// Attack: callerAddr is NOT allowlisted
vm.prank(callerAddr);
// Passes the extension check because owner=ownerAddr is allowlisted
pool.addLiquidity(ownerAddr, salt, deltas, callbackData, "");

// Assert: position created for ownerAddr despite callerAddr not being allowlisted
uint256 shares = pool.positionBinShares(ownerAddr, salt, binIdx);
assertGt(shares, 0); // succeeds — allowlist bypassed
```

The existing test suite inadvertently confirms this: `test_exactShares_canAddOnBehalfOfAnotherOwner` in `MetricOmmPoolLiquidityAdder.t.sol` demonstrates that `alice` can create a position for `bob` with no restriction, which in an allowlisted pool would be the exact bypass path. [8](#0-7)

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L182-196)
```text
  function addLiquidity(
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    bytes calldata callbackData,
    bytes calldata extensionData
  ) external nonReentrant(PoolActions.ADD_LIQUIDITY) returns (uint256 amount0Added, uint256 amount1Added) {
    if (deltas.binIdxs.length == 0) return (0, 0);
    if (deltas.binIdxs.length != deltas.shares.length) revert LiquidityDeltaLengthMismatch();
    _beforeAddLiquidity(msg.sender, owner, salt, deltas, extensionData);
    (amount0Added, amount1Added) = LiquidityLib.addLiquidity(
      _liquidityContext(), owner, salt, deltas, callbackData, binTotals, _binStates, _binTotalShares, _positionBinShares
    );
    _afterAddLiquidity(msg.sender, owner, salt, deltas, amount0Added, amount1Added, extensionData);
  }
```

**File:** metric-core/contracts/ExtensionCalling.sol (L95-98)
```text
    _callExtensionsInOrder(
      BEFORE_ADD_LIQUIDITY_ORDER,
      abi.encodeCall(IMetricOmmExtensions.beforeAddLiquidity, (sender, owner, salt, deltas, extensionData))
    );
```

**File:** metric-periphery/contracts/extensions/DepositAllowlistExtension.sol (L32-42)
```text
  function beforeAddLiquidity(address, address owner, uint80, LiquidityDelta calldata, bytes calldata)
    external
    view
    override
    returns (bytes4)
  {
    if (!allowAllDepositors[msg.sender] && !allowedDepositor[msg.sender][owner]) {
      revert IMetricOmmPoolActions.NotAllowedToDeposit();
    }
    return IMetricOmmExtensions.beforeAddLiquidity.selector;
  }
```

**File:** metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPoolActions.sol (L156-162)
```text
  function addLiquidity(
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    bytes calldata callbackData,
    bytes calldata extensionData
  ) external returns (uint256 amount0Added, uint256 amount1Added);
```

**File:** metric-periphery/test/MetricOmmPoolLiquidityAdder.t.sol (L211-220)
```text
  function test_exactShares_canAddOnBehalfOfAnotherOwner() public {
    LiquidityDelta memory d = _deltaAbovePrice(4, 10_000);
    address bob = makeAddr("bob");

    vm.prank(alice);
    helper.addLiquidityExactShares(address(pool), bob, 1, d, type(uint256).max, type(uint256).max, "");

    uint256 bobShares = stateView.positionBinShares(address(pool), bob, 1, int8(4));
    assertGt(bobShares, 0);
  }
```
