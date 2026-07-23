### Title
User-Controlled CREATE2 Salt Enables Address Collision to Drain Any MetricOmmPool — (`metric-core/contracts/MetricOmmPoolDeployer.sol`)

---

### Summary

`MetricOmmPoolDeployer.deploy()` uses a raw, user-supplied `salt` in a `new MetricOmmPool{salt: ...}(...)` CREATE2 deployment. An attacker can brute-force a salt collision between an undeployed pool address and an attacker-controlled contract, pre-set unlimited token allowances via a self-destructing contract, then deploy the real pool at the same address and drain all deposited funds.

---

### Finding Description

`PoolParameters` exposes a `bytes32 salt` field that flows from the caller through `createPool` into the deployer without any modification:

**`FactoryOperation.sol` line 35** — salt is a raw caller-supplied field: [1](#0-0) 

**`MetricOmmPoolFactory.sol` line 183** — factory passes it verbatim: [2](#0-1) 

**`MetricOmmPoolDeployer.sol` line 62** — deployer uses it directly in CREATE2: [3](#0-2) 

No mixing with `msg.sender`, `block.timestamp`, `block.number`, or any other entropy source occurs at any layer. `_validatePoolParameters` performs no check on the salt value. [4](#0-3) 

The resulting CREATE2 address is fully determined by `(deployer_address, salt, keccak256(MetricOmmPool_initcode))`. Because the attacker controls `salt`, they can brute-force a meet-in-the-middle collision between:

1. A set of undeployed `MetricOmmPool` addresses (by varying `salt` in `createPool`).
2. A set of attacker-controlled CREATE2 wallet/contract addresses (by varying their own salt).

Finding one collision across `2^80` candidates is feasible with commodity hardware (BTC-network-scale hashing reaches `2^80` in ~31 minutes).

---

### Impact Explanation

Once a colliding address `0xCOLLIDED` is found:

**Tx 1 (pre-setup):**
- Attacker deploys an attack contract to `0xCOLLIDED` via their own CREATE2.
- The contract calls `token0.approve(attacker, type(uint256).max)` and `token1.approve(attacker, type(uint256).max)`.
- The contract calls `selfdestruct` in the same transaction (valid post-Dencun per EIP-6780 when created in the same tx).

`0xCOLLIDED` now has zero bytecode but infinite allowances set.

**Tx 2 (pool deployment):**
- Attacker calls `createPool` with the colliding salt, deploying `MetricOmmPool` to `0xCOLLIDED`.
- The pool operates normally; LPs deposit token0 and token1.

**Tx 3 (drain):**
- Attacker calls `transferFrom(0xCOLLIDED, attacker, balance)` for both tokens, draining the entire pool.

All LP principal and accrued fees are stolen. The pool is rendered insolvent.

---

### Likelihood Explanation

- Any unprivileged caller can invoke `createPool` with an arbitrary salt — no role or whitelist restricts pool creation.
- The attacker can target any future pool by pre-computing the collision before deployment.
- The attacker can wait until the pool accumulates sufficient TVL before executing the drain, maximising profit.
- The computational cost is high but one-time and amortisable across any number of pools sharing the same deployer address and initcode.

Severity: **Medium** (high impact, high computational cost to exploit — consistent with the referenced Panoptic and Arcadia findings).

---

### Recommendation

Mix the salt with caller-uncontrollable entropy before passing it to CREATE2. The simplest fix is inside `MetricOmmPoolDeployer.deploy()`:

```solidity
// Before (vulnerable):
pool = address(new MetricOmmPool{salt: params.salt}(...));

// After (mitigated):
bytes32 effectiveSalt = keccak256(abi.encode(params.salt, params.token0, params.token1, params.priceProvider, block.number));
pool = address(new MetricOmmPool{salt: effectiveSalt}(...));
```

Including `block.number` forces the attacker to commit to a specific block, requiring sequencer collusion. Including `token0`, `token1`, and `priceProvider` ties the salt to pool-specific parameters that are validated by the factory, making cross-pool reuse of a found collision impossible.

Alternatively, remove the user-supplied salt entirely and derive it deterministically from `(token0, token1, priceProvider, nextPoolIdx)`.

---

### Proof of Concept

The two EVM properties required for this attack are demonstrable without an actual hash collision:

1. **A contract can be redeployed to an address that previously held a contract** — CREATE2 to the same address after `selfdestruct` succeeds.
2. **`approve` set by a self-destructed contract persists** — ERC-20 allowance storage survives `selfdestruct`; the new contract (the pool) inherits the pre-set allowance.

The attack flow maps directly onto the Metric OMM codebase:

```
salt (user input)
  └─► MetricOmmPoolFactory.createPool (line 183, passes salt verbatim)
        └─► MetricOmmPoolDeployer.deploy (line 62, new MetricOmmPool{salt: params.salt})
              └─► CREATE2 address = keccak256(0xff || DEPLOYER || salt || keccak256(initcode))
```

Because `DEPLOYER` and `keccak256(initcode)` are public constants, the attacker can pre-compute the full address space offline and find a collision with their own CREATE2 wallet before any pool is deployed.

### Citations

**File:** metric-core/contracts/types/FactoryOperation.sol (L35-35)
```text
  bytes32 salt;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L180-204)
```text
    pool = MetricOmmPoolDeployer(poolDeployer)
      .deploy(
        MetricOmmPoolDeployer.DeployParams({
        salt: params.salt,
        factory: address(this),
        admin: params.admin,
        adminFeeDestination: params.adminFeeDestination,
        token0: params.token0,
        token1: params.token1,
        priceProvider: params.priceProvider,
        extensions: poolExtensions,
        extensionOrders: params.extensionOrders,
        immutablePriceProvider: immutablePriceProvider,
        token0ScaleMultiplier: token0ScaleMultiplier,
        token1ScaleMultiplier: token1ScaleMultiplier,
        initialScaledAmount0PerShareE18: initialScaledAmount0PerShareE18,
        initialScaledAmount1PerShareE18: initialScaledAmount1PerShareE18,
        minimalMintableLiquidity: params.minimalMintableLiquidity,
        spreadFeeE6: spreadFeeE6,
        curBinDistFromProvidedPriceE6: params.curBinDistFromProvidedPriceE6,
        nonNegativeBinStates: nonNegativeBinStates,
        negativeBinStates: negativeBinStates,
        notionalFeeE8: notionalFeeE8
      })
      );
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L548-563)
```text
  function _validatePoolParameters(PoolParameters calldata params) internal view {
    if (params.token0 == address(0) || params.token1 == address(0) || params.token0 == params.token1) {
      revert InvalidTokenConfig();
    }
    if (params.admin == address(0)) revert InvalidAdmin();
    _validatePriceProvider(params.token0, params.token1, params.priceProvider);
    if (params.adminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    if (spreadProtocolFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    if (protocolNotionalFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();
    if (params.adminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (params.adminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
    if (params.initialAmount0PerShareE18 == 0 || params.initialAmount1PerShareE18 == 0) {
      revert InvalidInitialAmount();
    }
    if (params.minimalMintableLiquidity == 0) revert InvalidMinimalMintableLiquidity();
  }
```

**File:** metric-core/contracts/MetricOmmPoolDeployer.sol (L60-84)
```text
  function deploy(DeployParams calldata params) external onlyFactory returns (address pool) {
    pool = address(
      new MetricOmmPool{salt: params.salt}(
        params.factory,
        params.admin,
        params.adminFeeDestination,
        params.token0,
        params.token1,
        params.priceProvider,
        params.extensions,
        params.extensionOrders,
        params.immutablePriceProvider,
        params.token0ScaleMultiplier,
        params.token1ScaleMultiplier,
        params.initialScaledAmount0PerShareE18,
        params.initialScaledAmount1PerShareE18,
        params.minimalMintableLiquidity,
        params.spreadFeeE6,
        params.curBinDistFromProvidedPriceE6,
        params.nonNegativeBinStates,
        params.negativeBinStates,
        params.notionalFeeE8
      )
    );
  }
```
