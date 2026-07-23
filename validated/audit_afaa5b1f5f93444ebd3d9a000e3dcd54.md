The vulnerability is real. Here is the complete trace and finding.

---

### Title
`DepositAllowlistExtension.beforeAddLiquidity` Checks `owner` Instead of `sender`, Allowing Non-Allowlisted Callers to Bypass the Deposit Gate — (`metric-periphery/contracts/extensions/DepositAllowlistExtension.sol`)

---

### Summary

`DepositAllowlistExtension` is documented as gating `addLiquidity` **by depositor address**. Its `beforeAddLiquidity` hook silently discards the `sender` argument and checks only `owner`. Because `MetricOmmPool.addLiquidity` accepts a caller-supplied `owner` with no requirement that `msg.sender == owner`, any non-allowlisted address B can call `addLiquidity(owner=A)` where A is allowlisted, pass the extension check, pay the tokens via callback, and mint LP shares into A's position — all without being on the allowlist.

---

### Finding Description

**Step 1 — Pool entry point accepts arbitrary `owner`.**

`MetricOmmPool.addLiquidity` takes `owner` as a free parameter and imposes no `msg.sender == owner` constraint (contrast with `removeLiquidity` which does enforce `msg.sender == owner`): [1](#0-0) 

**Step 2 — Extension is called with both `sender` and `owner`.**

`_beforeAddLiquidity` forwards `msg.sender` as `sender` and the caller-supplied address as `owner`: [2](#0-1) 

**Step 3 — Extension ignores `sender` entirely and checks only `owner`.**

The first parameter is unnamed (discarded). The allowlist lookup uses `owner`: [3](#0-2) 

**Step 4 — Pool calls back to `msg.sender` (B) to collect tokens.**

`LiquidityLib.addLiquidity` invokes `IMetricOmmModifyLiquidityCallback(msg.sender).metricOmmModifyLiquidityCallback(...)`, so B's contract pays the tokens: [4](#0-3) 

**Result:** B (non-allowlisted) pays tokens, LP shares are minted to A's position key. The allowlist check on `owner` passes because A is allowlisted, but B — the actual economic actor — was never checked.

---

### Impact Explanation

The `DepositAllowlistExtension` is the sole mechanism for pools to restrict who may deposit. Its stated invariant ("Gates `addLiquidity` by depositor address") is broken: any address can deposit into a restricted pool by nominating an allowlisted address as `owner`. The access control is completely ineffective against a caller who is willing to pay tokens on behalf of another address. This constitutes broken core pool functionality for any pool relying on this extension for KYC, regulatory, or economic access control.

---

### Likelihood Explanation

The attack requires only a direct call to `pool.addLiquidity` with a crafted `owner` argument and a callback-implementing contract. No privileged role, no special token behavior, and no off-chain oracle manipulation is needed. Any address can execute this against any pool using `DepositAllowlistExtension`.

---

### Recommendation

Change `beforeAddLiquidity` to check `sender` (the actual caller/payer) rather than `owner`:

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

The `allowedDepositor` mapping and `setAllowedToDeposit` admin function should also be reviewed to ensure the semantics of "depositor" align with the actual payer identity.

---

### Proof of Concept

```solidity
// Pool configured with DepositAllowlistExtension; only address A is allowlisted.
// B is NOT allowlisted.

contract AttackerCallback is IMetricOmmModifyLiquidityCallback {
    IERC20 token0; IERC20 token1;
    constructor(address t0, address t1) { token0 = IERC20(t0); token1 = IERC20(t1); }

    function metricOmmModifyLiquidityCallback(uint256 a0, uint256 a1, bytes calldata) external {
        if (a0 > 0) token0.transfer(msg.sender, a0);
        if (a1 > 0) token1.transfer(msg.sender, a1);
    }
}

// B deploys AttackerCallback, funds it with tokens, then:
pool.addLiquidity(
    /* owner = */ addressA,   // allowlisted — passes the extension check
    salt,
    deltas,
    callbackData,
    extensionData
);
// Extension checks allowedDepositor[pool][A] → true → no revert
// Callback pulls tokens from AttackerCallback (B's contract)
// LP shares minted to A's position
// B successfully deposited despite not being allowlisted
``` [3](#0-2) [5](#0-4)

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

**File:** metric-core/contracts/ExtensionCalling.sol (L88-98)
```text
  function _beforeAddLiquidity(
    address sender,
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    bytes calldata extensionData
  ) internal {
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

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L144-149)
```text
      if (amount0Added > 0 || amount1Added > 0) {
        uint256 balance0Before = IERC20(ctx.token0).balanceOf(address(this));
        uint256 balance1Before = IERC20(ctx.token1).balanceOf(address(this));
        IMetricOmmModifyLiquidityCallback(msg.sender)
          .metricOmmModifyLiquidityCallback(amount0Added, amount1Added, callbackData);
        if (amount0Added > 0 && balance0Before + amount0Added > IERC20(ctx.token0).balanceOf(address(this))) {
```
