Now I have all the information needed. Let me trace the exact code path.

**`DepositAllowlistExtension.beforeAddLiquidity`** (the gating check):

```solidity
function beforeAddLiquidity(address, address owner, uint80, LiquidityDelta calldata, bytes calldata)
    external view override returns (bytes4)
{
    if (!allowAllDepositors[msg.sender] && !allowedDepositor[msg.sender][owner]) {
        revert IMetricOmmPoolActions.NotAllowedToDeposit();
    }
    return IMetricOmmExtensions.beforeAddLiquidity.selector;
}
```

The `sender` parameter (first `address,`) is **unnamed and completely ignored**. The check is only on `owner`. The contract is documented as "Gates `addLiquidity` by depositor address" but it gates by position owner, not by the actual depositor.

**`addLiquidityWeighted` with explicit owner** — `_validateOwner` only checks `owner != address(0)`, no restriction on who can specify whom as owner:

```solidity
function _validateOwner(address owner) internal pure {
    if (owner == address(0)) revert InvalidPositionOwner();
}
```

The probe phase framing in the question is a red herring. The bypass works through **any** `addLiquidity` path — direct pool call or through the LiquidityAdder — because the extension ignores `sender` entirely.

---

### Title
`DepositAllowlistExtension` gates position owner instead of actual depositor, allowing any disallowed depositor to bypass the allowlist — (`metric-periphery/contracts/extensions/DepositAllowlistExtension.sol`)

### Summary

`DepositAllowlistExtension.beforeAddLiquidity` ignores the `sender` argument (the actual caller/payer) and only checks `owner` (the position beneficiary). Any disallowed depositor can bypass the allowlist by specifying an allowlisted address as `owner`.

### Finding Description

`DepositAllowlistExtension` is documented as "Gates `addLiquidity` by depositor address, per pool." [1](#0-0) 

However, the `beforeAddLiquidity` implementation silently drops the `sender` parameter and checks only `owner`:

```solidity
function beforeAddLiquidity(address, address owner, ...)
    external view override returns (bytes4)
{
    if (!allowAllDepositors[msg.sender] && !allowedDepositor[msg.sender][owner]) {
        revert IMetricOmmPoolActions.NotAllowedToDeposit();
    }
    ...
}
``` [2](#0-1) 

The pool passes `msg.sender` (the actual caller) as `sender` and the position beneficiary as `owner` to the extension: [3](#0-2) [4](#0-3) 

A disallowed depositor can call `pool.addLiquidity(owner=allowlisted, ...)` directly, or call `MetricOmmPoolLiquidityAdder.addLiquidityWeighted(pool, owner=allowlisted, ...)`. In both cases:
- `sender` = disallowed depositor (ignored by extension)
- `owner` = allowlisted address (checked → passes)
- Tokens are pulled from the disallowed depositor
- LP shares are minted to the allowlisted owner's position

The `_validateOwner` check in `MetricOmmPoolLiquidityAdder` only rejects `address(0)`, placing no restriction on who can designate whom as owner: [5](#0-4) 

The probe phase mentioned in the question is irrelevant to the bypass — the same flaw exists in `addLiquidityExactShares` and in direct pool calls.

### Impact Explanation

A disallowed depositor can deposit tokens into any pool protected by `DepositAllowlistExtension` by routing through an allowlisted owner address. The allowlist — the pool's primary access control for liquidity provision — is completely bypassed. LP shares are minted from funds sourced from an unauthorized party. This breaks the core invariant the extension is designed to enforce.

### Likelihood Explanation

The attack requires only knowing one allowlisted address (publicly readable from `allowedDepositor` mapping) and calling a public function. No privileged access, no special setup, no flash loan needed. Any disallowed depositor can execute this immediately.

### Recommendation

Change `beforeAddLiquidity` to check `sender` (the actual depositor/caller) instead of `owner`:

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

Note: when the pool is called through `MetricOmmPoolLiquidityAdder`, `sender` will be the adder contract address, not the end user. If per-user gating through the adder is required, the adder's `msg.sender` must be forwarded through `extensionData` and decoded in the extension, or the adder itself must be the allowlisted entity.

### Proof of Concept

```solidity
// depositor = disallowed, owner = allowlisted
address depositor = makeAddr("disallowed");
address owner = makeAddr("allowlisted");

// allowlist only owner, not depositor
depositExtension.setAllowedToDeposit(address(pool), owner, true);

// fund depositor and approve
token0.mint(depositor, 1e18);
token1.mint(depositor, 1e18);
vm.startPrank(depositor);
token0.approve(address(pool), type(uint256).max);
token1.approve(address(pool), type(uint256).max);

// call pool directly with allowlisted owner — extension checks owner, passes
LiquidityDelta memory d = ...;
pool.addLiquidity(owner, 0, d, abi.encode(...), "");
vm.stopPrank();

// LP shares minted to owner, funded by disallowed depositor
uint256 shares = positionBinShares(address(pool), owner, 0, binIdx);
assertGt(shares, 0); // bypass confirmed
```

### Citations

**File:** metric-periphery/contracts/extensions/DepositAllowlistExtension.sol (L10-13)
```text
/// @title DepositAllowlistExtension
/// @notice Gates `addLiquidity` by depositor address, per pool.
contract DepositAllowlistExtension is BaseMetricExtension, IDepositAllowlistExtension {
  mapping(address pool => mapping(address depositor => bool)) public allowedDepositor;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L191-191)
```text
    _beforeAddLiquidity(msg.sender, owner, salt, deltas, extensionData);
```

**File:** metric-core/contracts/ExtensionCalling.sol (L95-98)
```text
    _callExtensionsInOrder(
      BEFORE_ADD_LIQUIDITY_ORDER,
      abi.encodeCall(IMetricOmmExtensions.beforeAddLiquidity, (sender, owner, salt, deltas, extensionData))
    );
```

**File:** metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol (L247-249)
```text
  function _validateOwner(address owner) internal pure {
    if (owner == address(0)) revert InvalidPositionOwner();
  }
```
