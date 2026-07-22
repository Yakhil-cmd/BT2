### Title
Factory Owner Cannot Replace Compromised Pool Admin, Enabling Permanent Admin Fee Theft — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`proposePoolAdminTransfer` is exclusively gated by `onlyPoolAdmin`. The factory owner has no emergency path to override `poolAdmin[pool]`. If a pool admin key is compromised, the attacker can immediately redirect `poolAdminFeeDestination` to a controlled address, and the permissionless `collectPoolFees` will drain all accrued and future admin fees to the attacker with no recourse.

### Finding Description
The admin transfer flow in `MetricOmmPoolFactory` is a strict two-step process initiated only by the current pool admin:

```solidity
// MetricOmmPoolFactory.sol:510
function proposePoolAdminTransfer(address pool, address newAdmin)
    external override nonReentrant onlyPoolAdmin(pool)
{
    ...
    pendingPoolAdmin[pool] = newAdmin;
}
``` [1](#0-0) 

The `onlyPoolAdmin` modifier checks exclusively `msg.sender != poolAdmin[pool]`: [2](#0-1) 

The factory owner's entire function surface (`setPoolDeployer`, `collectTokens`, `setFeeCaps`, `setPoolProtocolFee`, `protocolPausePool`, `protocolUnpausePool`) contains no function that writes to `poolAdmin[pool]`: [3](#0-2) 

A compromised pool admin can immediately call `setPoolAdminFeeDestination` to redirect the admin fee sweep target:

```solidity
// MetricOmmPoolFactory.sol:438
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    poolAdminFeeDestination[pool] = newAdminFeeDestination;
}
``` [4](#0-3) 

`collectPoolFees` is **permissionless** — any address can call it, so the attacker does not even need to call it themselves; keepers or bots will drain admin fees to the attacker's address automatically: [5](#0-4) 

Additionally, for pools with a mutable oracle (`priceProviderTimelock < type(uint256).max`), the compromised admin can call `proposePoolPriceProvider` with a malicious oracle and, after the timelock, execute it via `executePoolPriceProviderUpdate` — both gated exclusively by `onlyPoolAdmin`: [6](#0-5) 

### Impact Explanation
**Direct loss of protocol fees / owed admin assets.** Once `poolAdminFeeDestination` is redirected, every subsequent `collectPoolFees` call (permissionless, callable by anyone) transfers the admin share of all accrued spread and notional fees to the attacker. The factory owner cannot stop this: `protocolPausePool` halts swaps (preventing new fee accrual) but does not reverse the destination change or recover already-accrued fees. There is no owner-callable function that writes `poolAdmin[pool]` or `poolAdminFeeDestination[pool]`.

Secondary impact: on mutable-oracle pools, the compromised admin can schedule and execute a price provider that returns manipulated bid/ask prices, enabling bad-price execution and swap conservation failure after the timelock elapses.

### Likelihood Explanation
Low. Requires the pool admin key to be compromised (private key leak or seizure). The docs recommend a multisig, but the contract does not enforce it. Any pool deployed with an EOA admin is immediately vulnerable to this scenario with no protocol-level recovery path.

### Recommendation
Add a factory-owner override function that can forcibly replace `poolAdmin[pool]` in an emergency, analogous to how the external protocol's recommendation was to allow the owner to call `setLiquidityProvider`:

```solidity
function forceReplacePoolAdmin(address pool, address newAdmin) external onlyOwner {
    if (newAdmin == address(0)) revert InvalidAdmin();
    address previous = poolAdmin[pool];
    poolAdmin[pool] = newAdmin;
    delete pendingPoolAdmin[pool];
    emit PoolAdminTransferred(pool, previous, newAdmin);
}
```

This preserves the normal two-step flow for routine transfers while giving the factory owner an emergency escape hatch when the pool admin key is compromised.

### Proof of Concept

1. Pool is deployed with `admin = EOA_ADMIN` (or a compromised multisig).
2. Attacker obtains `EOA_ADMIN`'s private key.
3. Attacker calls `factory.setPoolAdminFeeDestination(pool, ATTACKER)` — succeeds because `msg.sender == poolAdmin[pool]`.
4. Any address (keeper, bot, or attacker) calls `factory.collectPoolFees(pool)` — permissionless; admin fee share is transferred to `ATTACKER`.
5. Factory owner calls `factory.protocolPausePool(pool)` — halts new swaps but cannot change `poolAdminFeeDestination` or recover already-redirected fees.
6. Factory owner has no function to call `poolAdmin[pool] = safeAddress` — the pool admin role is permanently held by the attacker until they voluntarily transfer it.
7. For mutable-oracle pools: attacker calls `factory.proposePoolPriceProvider(pool, MALICIOUS_ORACLE)`, waits for `priceProviderTimelock[pool]` seconds, then calls `factory.executePoolPriceProviderUpdate(pool)` — pool now prices all swaps against a manipulated oracle.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L122-129)
```text
  function _checkPoolAdmin(address pool) private view {
    if (msg.sender != poolAdmin[pool]) revert NotPoolAdmin();
  }

  modifier onlyPoolAdmin(address pool) {
    _checkPoolAdmin(pool);
    _;
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L252-403)
```text
  // ============ External: factory owner ============

  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function setPoolDeployer(address _poolDeployer) external override onlyOwner {
    if (poolDeployer != address(0)) revert PoolDeployerAlreadySet();
    poolDeployer = _poolDeployer;
    emit PoolDeployerSet(_poolDeployer);
  }

  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function collectTokens(address token, address to, uint256 amount) external override onlyOwner {
    uint256 balance = IERC20(token).balanceOf(address(this));
    uint256 amountToCollect = amount == 0 ? balance : amount;
    if (amountToCollect > 0) {
      IERC20(token).safeTransfer(to, amountToCollect);
      emit TokensCollected(token, to, amountToCollect);
    }
  }

  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function collectEth(address payable to, uint256 amount) external override onlyOwner {
    uint256 balance = address(this).balance;
    uint256 amountToCollect = amount == 0 ? balance : amount;
    if (amountToCollect > 0) {
      (bool success,) = to.call{value: amountToCollect}("");
      require(success, "ETH transfer failed");
      emit TokensCollected(address(0), to, amountToCollect);
    }
  }
  receive() external payable {}

  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function setFeeCaps(
    uint24 newMaxProtocolSpreadFeeE6,
    uint24 newMaxAdminSpreadFeeE6,
    uint24 newMaxProtocolNotionalFeeE8,
    uint24 newMaxAdminNotionalFeeE8
  ) external override onlyOwner {
    if (
      newMaxProtocolSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6 || newMaxAdminSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6
        || newMaxProtocolNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8 || newMaxAdminNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8
    ) {
      revert FeeCapsExceedHardLimit();
    }
    maxProtocolSpreadFeeE6 = newMaxProtocolSpreadFeeE6;
    maxAdminSpreadFeeE6 = newMaxAdminSpreadFeeE6;
    maxProtocolNotionalFeeE8 = newMaxProtocolNotionalFeeE8;
    maxAdminNotionalFeeE8 = newMaxAdminNotionalFeeE8;

    if (spreadProtocolFeeE6 > newMaxProtocolSpreadFeeE6) {
      uint24 oldFeeE6 = spreadProtocolFeeE6;
      spreadProtocolFeeE6 = newMaxProtocolSpreadFeeE6;
      emit SpreadProtocolFeeDefaultUpdated(oldFeeE6, newMaxProtocolSpreadFeeE6);
    }
    if (protocolNotionalFeeE8 > newMaxProtocolNotionalFeeE8) {
      uint24 oldFeeE8 = protocolNotionalFeeE8;
      protocolNotionalFeeE8 = newMaxProtocolNotionalFeeE8;
      emit ProtocolNotionalFeeDefaultUpdated(oldFeeE8, newMaxProtocolNotionalFeeE8);
    }

    emit FeeCapsUpdated(
      newMaxProtocolSpreadFeeE6, newMaxAdminSpreadFeeE6, newMaxProtocolNotionalFeeE8, newMaxAdminNotionalFeeE8
    );
  }

  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function setPoolProtocolFee(address pool, uint24 newProtocolSpreadFeeE6, uint24 newProtocolNotionalFeeE8)
    external
    override
    onlyOwner
    nonReentrant
  {
    if (newProtocolSpreadFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    if (newProtocolNotionalFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();

    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );

    uint24 aSpread = c.adminSpreadFeeE6;
    uint24 aNotional = c.adminNotionalFeeE8;
    if (aSpread > maxAdminSpreadFeeE6) {
      aSpread = maxAdminSpreadFeeE6;
      emit PoolAdminSpreadFeeUpdated(pool, aSpread);
    }
    if (aNotional > maxAdminNotionalFeeE8) {
      aNotional = maxAdminNotionalFeeE8;
      emit PoolAdminNotionalFeeUpdated(pool, aNotional);
    }

    c = PoolFeeConfig({
      protocolSpreadFeeE6: newProtocolSpreadFeeE6,
      adminSpreadFeeE6: aSpread,
      protocolNotionalFeeE8: newProtocolNotionalFeeE8,
      adminNotionalFeeE8: aNotional
    });
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
    emit PoolProtocolSpreadFeeUpdated(pool, newProtocolSpreadFeeE6);
    emit PoolProtocolNotionalFeeUpdated(pool, newProtocolNotionalFeeE8);
  }

  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function setDefaultSpreadProtocolFeeE6(uint24 newFeeE6) external override onlyOwner {
    if (newFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    uint24 oldFeeE6 = spreadProtocolFeeE6;
    spreadProtocolFeeE6 = newFeeE6;
    emit SpreadProtocolFeeDefaultUpdated(oldFeeE6, newFeeE6);
  }

  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function setDefaultProtocolNotionalFeeE8(uint24 newFeeE8) external override onlyOwner {
    if (newFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();
    uint24 oldFeeE8 = protocolNotionalFeeE8;
    protocolNotionalFeeE8 = newFeeE8;
    emit ProtocolNotionalFeeDefaultUpdated(oldFeeE8, newFeeE8);
  }

  /// @inheritdoc IMetricOmmPoolFactory
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

  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(2);
  }

  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L438-447)
```text
  function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L473-507)
```text
  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
  function proposePoolPriceProvider(address pool, address newPriceProvider)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    PoolImmutables memory p = IMetricOmmPool(pool).getImmutables();
    uint256 timelock = priceProviderTimelock[pool];
    if (p.immutablePriceProvider != address(0)) revert PriceProviderImmutable();
    _validatePriceProvider(p.token0, p.token1, newPriceProvider);

    address mutableProvider = PoolStateLibrary._slot3(pool);
    address current = mutableProvider != address(0) ? mutableProvider : p.immutablePriceProvider;
    uint256 executeAfter = block.timestamp + timelock;
    pendingPriceProvider[pool] = newPriceProvider;
    pendingPriceProviderExecuteAfter[pool] = executeAfter;
    emit PoolPriceProviderChangeProposed(pool, current, newPriceProvider, executeAfter);
  }

  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
  function executePoolPriceProviderUpdate(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    address pending = pendingPriceProvider[pool];
    if (pending == address(0)) revert NoPriceProviderChangeProposed();
    uint256 execAfter = pendingPriceProviderExecuteAfter[pool];
    // forge-lint: disable-next-line(block-timestamp) -- timelock enforcement legitimately relies on `block.timestamp`.
    if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(execAfter, block.timestamp);
    PoolImmutables memory p = IMetricOmmPool(pool).getImmutables();
    if (p.immutablePriceProvider != address(0)) revert PriceProviderImmutable();
    _validatePriceProvider(p.token0, p.token1, pending);
    IMetricOmmPoolFactoryActions(pool).setPriceProvider(pending);
    delete pendingPriceProvider[pool];
    delete pendingPriceProviderExecuteAfter[pool];
    emit PoolPriceProviderUpdated(pool, pending);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L509-515)
```text
  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
  function proposePoolAdminTransfer(address pool, address newAdmin) external override nonReentrant onlyPoolAdmin(pool) {
    if (newAdmin == address(0)) revert InvalidAdmin();
    if (newAdmin == poolAdmin[pool]) revert InvalidAdmin();
    pendingPoolAdmin[pool] = newAdmin;
    emit PoolAdminTransferProposed(pool, poolAdmin[pool], newAdmin);
  }
```

**File:** metric-core/contracts/interfaces/IMetricOmmPoolFactory/IMetricOmmPoolFactory.sol (L159-163)
```text
  // ============ Mutating: Fee collection (permissionless) ============

  /// @notice Pull accrued protocol and admin fees from `pool` using stored `poolFeeConfig` splits.
  /// @dev Callable by any address (keepers, admins, or bots). Does not change fee configuration.
  function collectPoolFees(address pool) external;
```
