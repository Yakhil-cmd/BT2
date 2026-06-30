### Title
Hardcoded Stale NEAR-to-EVM Gas Conversion Ratio Causes Systematic Undercharging in XCC Precompile, Leading to Engine Insolvency - (File: engine-precompiles/src/xcc.rs)

---

### Summary

The `CrossContractCall` precompile charges users EVM gas for the NEAR gas they attach to cross-contract calls using a single hardcoded constant `CROSS_CONTRACT_CALL_NEAR_GAS = 175_000_000`. This ratio was derived from a static, point-in-time benchmark report and is baked into the contract with no mechanism to update it. If NEAR's actual gas pricing diverges from this hardcoded ratio — which it can through NEAR protocol upgrades — the engine systematically undercharges users in EVM gas for the NEAR gas it actually expends, leading to insolvency.

---

### Finding Description

In `engine-precompiles/src/xcc.rs`, the `CrossContractCall` precompile computes the EVM gas cost to charge the caller for attaching NEAR gas to a promise:

```rust
// engine-precompiles/src/xcc.rs, line 174
cost += EthGas::new(promise.attached_gas.as_u64() / costs::CROSS_CONTRACT_CALL_NEAR_GAS);
```

The divisor `CROSS_CONTRACT_CALL_NEAR_GAS` is a compile-time constant:

```rust
// engine-precompiles/src/xcc.rs, lines 40-45
/// EVM gas cost per NEAR gas attached to the created promise.
/// This value is derived from the gas report `https://hackmd.io/@birchmd/Sy4piXQ29`
/// The units on this quantity are `NEAR Gas / EVM Gas`.
/// The report gives a value `0.175 T(NEAR_gas) / k(EVM_gas)`. To convert the units to
/// `NEAR Gas / EVM Gas`, we simply multiply `0.175 * 10^12 / 10^3 = 175 * 10^6`.
pub const CROSS_CONTRACT_CALL_NEAR_GAS: u64 = 175_000_000;
```

This constant encodes the assumption that 1 EVM gas corresponds to 175,000,000 NEAR gas (0.175 TGas). The value was derived from a single static benchmark document, not a live oracle or on-chain parameter. There is no mechanism to update this ratio without a full contract upgrade.

The same ratio is used in the test suite to validate the precompile's gas cost:

```rust
// engine-tests/src/tests/xcc.rs, lines 122-124
let xcc_base_cost = EthGas::new(xcc_base_cost.as_u64() / costs::CROSS_CONTRACT_CALL_NEAR_GAS);
let xcc_cost_per_byte = xcc_cost_per_byte / costs::CROSS_CONTRACT_CALL_NEAR_GAS;
```

This is structurally identical to the external report's root cause: `FeeOracleV1.feeFor()` hardcodes the assumption that data availability uses EVM calldata pricing, while Aurora's XCC precompile hardcodes the assumption that the NEAR/EVM gas exchange rate is permanently fixed at 175,000,000.

---

### Impact Explanation

**Impact: Critical — Insolvency**

The engine is the party that actually pays NEAR gas when dispatching XCC promises. It recovers this cost by charging the EVM caller EVM gas, which is then converted to ETH/wETH fees. If `CROSS_CONTRACT_CALL_NEAR_GAS` is set too high relative to the true ratio (i.e., the constant overestimates how much NEAR gas each EVM gas unit covers), the formula `attached_near_gas / CROSS_CONTRACT_CALL_NEAR_GAS` produces an EVM gas charge that is too small. The engine pays out more NEAR gas than it collects in EVM fees for every XCC call, draining the engine's NEAR balance over time.

Concretely: if the true ratio is 100,000,000 NEAR gas per EVM gas but the constant is 175,000,000, a user attaching 1 TGas pays only ~5,714 EVM gas instead of the correct ~10,000 EVM gas — a 43% undercharge per call. At scale, this is a direct path to insolvency.

---

### Likelihood Explanation

**Likelihood: Medium**

NEAR Protocol has changed its gas pricing model in the past through protocol upgrades (e.g., storage cost changes, host function repricing). The ratio `0.175 T(NEAR_gas) / k(EVM_gas)` was measured at a specific point in time. Any NEAR protocol upgrade that reprices WASM execution, host function calls, or storage operations will silently invalidate this constant. Because the constant is compiled into the contract, it cannot be corrected without a full engine upgrade, and the window of insolvency between a NEAR repricing event and an engine upgrade can be exploited by any EVM user who calls the XCC precompile with large `attached_gas` values.

The entry path requires no privilege: any EVM user or contract can call the `CrossContractCall` precompile at address `0x516cded1d16af10cad47d6d49128e2eb7d27b372` with an `Eager` XCC call carrying a large `attached_gas` field.

---

### Recommendation

Replace the hardcoded `CROSS_CONTRACT_CALL_NEAR_GAS` constant with an on-chain configurable parameter stored in engine state, updatable by the engine owner. This mirrors the recommendation in the external report to replace hardcoded pricing assumptions with a parameterized struct. The ratio should be re-calibrated whenever NEAR Protocol reprices gas-relevant operations, and the engine should expose an admin method to update it without a full contract upgrade.

---

### Proof of Concept

1. NEAR Protocol upgrades its gas pricing such that the true NEAR-gas-per-EVM-gas ratio drops from 175,000,000 to 100,000,000.
2. An EVM user calls the XCC precompile with `CrossContractCallArgs::Eager` and `attached_gas = 10_000_000_000_000` (10 TGas).
3. The precompile computes: `cost += EthGas::new(10_000_000_000_000 / 175_000_000)` = **57,142 EVM gas** charged to the user.
4. The engine dispatches the promise and pays **10 TGas** of actual NEAR gas.
5. The correct EVM charge at the true ratio would be: `10_000_000_000_000 / 100_000_000` = **100,000 EVM gas**.
6. The engine is undercharged by **42,858 EVM gas** per call. Repeated at scale, the engine's NEAR balance is drained faster than EVM fees replenish it, causing insolvency.

**Root cause lines:** [1](#0-0) [2](#0-1)

### Citations

**File:** engine-precompiles/src/xcc.rs (L40-45)
```rust
    /// EVM gas cost per NEAR gas attached to the created promise.
    /// This value is derived from the gas report `https://hackmd.io/@birchmd/Sy4piXQ29`
    /// The units on this quantity are `NEAR Gas / EVM Gas`.
    /// The report gives a value `0.175 T(NEAR_gas) / k(EVM_gas)`. To convert the units to
    /// `NEAR Gas / EVM Gas`, we simply multiply `0.175 * 10^12 / 10^3 = 175 * 10^6`.
    pub const CROSS_CONTRACT_CALL_NEAR_GAS: u64 = 175_000_000;
```

**File:** engine-precompiles/src/xcc.rs (L174-175)
```rust
        cost += EthGas::new(promise.attached_gas.as_u64() / costs::CROSS_CONTRACT_CALL_NEAR_GAS);
        check_cost(cost)?;
```
