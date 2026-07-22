### Title
`DepositAllowlistExtension` Gates Position Owner Instead of Payer, Allowing Non-Allowlisted Users to Bypass Deposit Restrictions — (`metric-periphery/contracts/extensions/DepositAllowlistExtension.sol`)

### Summary
`DepositAllowlistExtension.beforeAddLiquidity` ignores the `sender` argument and checks only the `owner` (position recipient). Because `MetricOmmPool.addLiquidity` and `MetricOmmPoolLiquidityAdder` both accept an arbitrary caller-supplied `owner` address with no identity binding to `msg.sender`, any non-allowlisted user can bypass the deposit gate by naming an allowlisted address as the position owner.

### Finding Description

`DepositAllowlistExtension.beforeAddLiquidity` silently discards the first argument (`sender`) and checks only `owner`:

```solidity
function beforeAddLiquidity(address, address owner, uint80, LiquidityDelta calldata, bytes calldata)
    external view override returns (bytes4)
{
    if (!allowAllDepositors[msg.sender] && !allowedDepositor[msg.sender][owner]) {
        revert IMetricOmmPoolActions.NotAllowedToDeposit();
    }
    return IMetricOmmExtensions.beforeAddLiquidity.selector;
}
``` [1](#0-0) 

`MetricOmmPool.addLiquidity` passes `msg.sender` as `sender` and the caller-supplied `owner` as `owner` to the extension:

```solidity
_beforeAddLiquidity(msg.sender, owner, salt, deltas, extensionData);
``` [2](#0-1) 

`MetricOmmPoolLiquidityAdder.addLiquidityExactShares` accepts an arbitrary `owner` parameter and validates only that it is non-zero:

```solidity
function addLiquidityExactShares(
    address pool,
    address owner,
    ...
) external payable override returns (...) {
    _validateOwner(owner);   // only checks owner != address(0)
    ...
    return _addLiquidity(pool, owner, salt, deltas, msg.sender, ...);
}
``` [3](#0-2) 

`_validateOwner` performs no identity binding between `owner` and `msg.sender`: [4](#0-3) 

The same pattern applies to `addLiquidityWeighted(pool, owner, ...)`: [5](#0-4) 

**Attack path:**

1. Pool admin deploys a pool with `DepositAllowlistExtension` and allowlists only `alice`.
2. Non-allowlisted `bob` calls `addLiquidityExactShares(pool, alice, salt, deltas, max0, max1, extensionData)` directly on the pool or via the LiquidityAdder.
3. The extension evaluates `allowedDepositor[pool][alice]` → `true` → passes.
4. `bob` pays the tokens (via the `metricOmmModifyLiquidityCallback`); `alice` receives the LP shares.
5. The deposit allowlist is bypassed: `bob`'s tokens enter the pool and alter its liquidity composition without `bob` ever being allowlisted.

This bypass works even without the LiquidityAdder — `bob` can call `pool.addLiquidity(alice, ...)` directly and implement the callback himself.

The protocol's own audit-target document explicitly flags this identity-separation risk:

> *"The attacker can separate payer from owner and can route through the liquidity adder, so the checked identity has to be exactly the one the pool intends to gate."* [6](#0-5) 

### Impact Explanation

The `DepositAllowlistExtension` is the sole on-chain mechanism for restricting who may add liquidity to a pool. Bypassing it allows non-allowlisted parties to inject arbitrary token amounts into the pool, altering bin balances, LP share dilution, and fee accrual in ways the pool admin did not authorize. This breaks the core pool-access invariant the extension is designed to enforce.

### Likelihood Explanation

The bypass requires no special privileges, no oracle manipulation, and no prerequisite admin action. Any address that knows an allowlisted `owner` address (which is public on-chain via `AllowedToDepositSet` events) can execute it permissionlessly. Likelihood is **Medium** because it requires awareness of the allowlist state, but the information is freely available.

### Recommendation

The extension should gate the **economically relevant actor** — the address that actually pays tokens and initiates the call. Two complementary fixes:

1. **In `DepositAllowlistExtension.beforeAddLiquidity`**: check `sender` (the direct caller of `pool.addLiquidity`) instead of, or in addition to, `owner`:
   ```solidity
   function beforeAddLiquidity(address sender, address owner, ...) external view override returns (bytes4) {
       if (!allowAllDepositors[msg.sender]
           && !allowedDepositor[msg.sender][sender]   // gate the payer/initiator
           && !allowedDepositor[msg.sender][owner]) { // optionally also gate owner
           revert IMetricOmmPoolActions.NotAllowedToDeposit();
       }
       ...
   }
   ```

2. **In `MetricOmmPoolLiquidityAdder`**: enforce `owner == msg.sender` (or require explicit pool-admin approval for third-party deposits) so the payer and position owner cannot be decoupled without consent.

### Proof of Concept

```solidity
// Pool has DepositAllowlistExtension; only `alice` is allowlisted.
// `bob` is NOT allowlisted.

// bob calls directly on the pool:
pool.addLiquidity(
    alice,          // owner — allowlisted, passes the extension check
    salt,
    deltas,
    callbackData,   // bob implements metricOmmModifyLiquidityCallback to pay
    extensionData
);
// Result: extension sees allowedDepositor[pool][alice] == true → no revert.
// bob's tokens enter the pool; alice receives LP shares.
// The allowlist is bypassed.
```

### Citations

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

**File:** metric-core/contracts/MetricOmmPool.sol (L191-191)
```text
    _beforeAddLiquidity(msg.sender, owner, salt, deltas, extensionData);
```

**File:** metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol (L56-68)
```text
  function addLiquidityExactShares(
    address pool,
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    uint256 maxAmountToken0,
    uint256 maxAmountToken1,
    bytes calldata extensionData
  ) external payable override returns (uint256 amount0Added, uint256 amount1Added) {
    _validateOwner(owner);
    _validateDeltas(deltas);
    return _addLiquidity(pool, owner, salt, deltas, msg.sender, maxAmountToken0, maxAmountToken1, extensionData);
  }
```

**File:** metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol (L88-116)
```text
  function addLiquidityWeighted(
    address pool,
    address owner,
    uint80 salt,
    LiquidityDelta calldata weightDeltas,
    uint256 maxAmountToken0,
    uint256 maxAmountToken1,
    int8 minimalCurBin,
    uint104 minimalPosition,
    int8 maximalCurBin,
    uint104 maximalPosition,
    bytes calldata extensionData
  ) external payable override returns (uint256 amount0Added, uint256 amount1Added) {
    _validateOwner(owner);
    _validateDeltas(weightDeltas);
    _validatePositiveWeights(weightDeltas);
    _validateBinAndBinPosition(pool, minimalCurBin, minimalPosition, maximalCurBin, maximalPosition);

    try IMetricOmmPoolActions(pool)
      .addLiquidity(owner, salt, weightDeltas, abi.encode(KIND_PROBE), extensionData) returns (
      uint256, uint256
    ) {
      revert WeightedProbeInconclusive();
    } catch (bytes memory reason) {
      (uint256 need0, uint256 need1) = _decodeLiquidityProbeOrBubble(reason);
      LiquidityDelta memory scaled = _scaleWeightsToShares(weightDeltas, maxAmountToken0, maxAmountToken1, need0, need1);
      return _addLiquidity(pool, owner, salt, scaled, msg.sender, maxAmountToken0, maxAmountToken1, extensionData);
    }
  }
```

**File:** metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol (L247-249)
```text
  function _validateOwner(address owner) internal pure {
    if (owner == address(0)) revert InvalidPositionOwner();
  }
```

**File:** generate_scanned_questions.py (L651-653)
```python
            values="the identity actually checked against the allowlist and whether a disallowed depositor can still mint LP shares",
            control_hint="The attacker can separate payer from owner and can route through the liquidity adder, so the checked identity has to be exactly the one the pool intends to gate.",
            validation_focus="Exercise direct pool adds and liquidity-adder adds with mismatched owner/payer pairs and assert the allowlist always gates the economically relevant depositor.",
```
