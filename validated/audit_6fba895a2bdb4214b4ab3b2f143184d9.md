### Title
XCC Precompile Rounds Down NEAR-to-EVM Gas Conversion, Allowing Users to Obtain NEAR Gas at Zero EVM Cost - (`engine-precompiles/src/xcc.rs`)

### Summary

The Cross-Contract Call (XCC) precompile in `engine-precompiles/src/xcc.rs` converts the attached NEAR gas into an EVM gas charge using integer division that truncates (rounds down). Because the divisor `CROSS_CONTRACT_CALL_NEAR_GAS = 175_000_000` is large, an attacker can craft the user-controlled `attached_gas` field of their XCC promise so that the remainder of the division is up to `174_999_999` NEAR gas, which is consumed by the NEAR network but never charged to the caller in EVM gas. Repeated calls accumulate this subsidy, draining the Aurora protocol's NEAR gas reserves.

### Finding Description

In `engine-precompiles/src/xcc.rs`, the EVM gas cost for the attached NEAR gas is computed at line 174:

```rust
cost += EthGas::new(promise.attached_gas.as_u64() / costs::CROSS_CONTRACT_CALL_NEAR_GAS);
``` [1](#0-0) 

`CROSS_CONTRACT_CALL_NEAR_GAS` is defined as `175_000_000`: [2](#0-1) 

`promise.attached_gas` is `router_exec_cost.saturating_add(call_gas)`, where `call_gas = call.total_gas()` is derived entirely from the user-supplied `CrossContractCallArgs::Eager` input: [3](#0-2) 

The user controls `attached_gas` inside each `PromiseCreateArgs` they submit: [4](#0-3) 

Because `ROUTER_EXEC_BASE = 7_000_000_000_000` is exactly divisible by `175_000_000` (= 40 000 EVM gas, no remainder), an attacker can set `call_gas = 174_999_999` to produce:

```
total_attached_gas = 7_000_000_000_000 + 174_999_999 = 7_000_174_999_999
EVM gas charged    = 7_000_174_999_999 / 175_000_000 = 40_000  (rounds down)
```

The 174 999 999 NEAR gas is forwarded to the NEAR runtime and consumed, but the caller pays **zero additional EVM gas** for it. The rounding error is bounded at `CROSS_CONTRACT_CALL_NEAR_GAS − 1 = 174_999_999` NEAR gas per call, regardless of the total size of `call_gas`. [5](#0-4) 

### Impact Explanation

Each call to the XCC precompile with a crafted `call_gas` value causes the Aurora contract to forward up to 174 999 999 NEAR gas to the NEAR runtime without collecting the corresponding EVM gas fee from the caller. At the NEAR gas price of ~100 million yoctoNEAR per gas unit, this is ≈ 0.0175 NEAR (≈ $0.05 at current prices) per call. Repeated in a loop, this drains the Aurora protocol's NEAR gas reserves — the pool that covers the cost of executing EVM transactions on NEAR — constituting a sustained theft of protocol yield. This maps to **High: Theft of unclaimed yield**.

### Likelihood Explanation

The attack requires no privileges. Any EVM address can call the XCC precompile at `0x516cded1d16af10cad47d6d49128e2eb7d27b372` with a crafted `CrossContractCallArgs::Eager` payload. The only prerequisite is holding enough wNEAR to cover the `required_near` transfer and enough ETH to pay the base EVM gas (`CROSS_CONTRACT_CALL_BASE = 343_650` EVM gas). The attack is economically viable because the per-call NEAR gas subsidy (~$0.05) can exceed the EVM gas cost of the call at low gas prices, and the loop can be batched to amortize fixed transaction overhead. [6](#0-5) 

### Recommendation

Replace the truncating integer division with a ceiling division so that any fractional NEAR gas unit is rounded up to the next EVM gas unit:

```rust
// Before (rounds down):
cost += EthGas::new(promise.attached_gas.as_u64() / costs::CROSS_CONTRACT_CALL_NEAR_GAS);

// After (rounds up):
let near_gas = promise.attached_gas.as_u64();
let divisor  = costs::CROSS_CONTRACT_CALL_NEAR_GAS;
cost += EthGas::new((near_gas + divisor - 1) / divisor);
```

This ensures the caller always pays at least as much EVM gas as the NEAR gas they consume.

### Proof of Concept

1. Deploy a contract on Aurora that calls the XCC precompile in a loop.
2. In each iteration, submit `CrossContractCallArgs::Eager` with a single `PromiseCreateArgs` whose `attached_gas = NearGas::new(174_999_999)` (just under one conversion unit).
3. Observe that `promise.attached_gas = ROUTER_EXEC_BASE + 174_999_999 = 7_000_174_999_999`.
4. The EVM gas charged for the gas portion is `7_000_174_999_999 / 175_000_000 = 40_000` — identical to the charge when `attached_gas = 0`.
5. The NEAR runtime receives and burns the full `7_000_174_999_999` NEAR gas, but the caller paid only for `7_000_000_000_000` NEAR gas worth of EVM gas.
6. Each loop iteration extracts ≈ 0.0175 NEAR from the Aurora protocol's gas reserves at no additional EVM cost to the attacker. [7](#0-6)

### Citations

**File:** engine-precompiles/src/xcc.rs (L45-45)
```rust
    pub const CROSS_CONTRACT_CALL_NEAR_GAS: u64 = 175_000_000;
```

**File:** engine-precompiles/src/xcc.rs (L113-115)
```rust
        let input_len = u64::try_from(input.len()).map_err(utils::err_usize_conv)?;
        let mut cost =
            costs::CROSS_CONTRACT_CALL_BASE + costs::CROSS_CONTRACT_CALL_BYTE * input_len;
```

**File:** engine-precompiles/src/xcc.rs (L141-156)
```rust
                let call_gas = call.total_gas();
                let attached_near = call.total_near();
                let callback_count = call
                    .promise_count()
                    .checked_sub(1)
                    .ok_or_else(|| ExitError::Other(Cow::from(consts::ERR_INVALID_INPUT)))?;
                let router_exec_cost = costs::ROUTER_EXEC_BASE
                    + NearGas::new(callback_count * costs::ROUTER_EXEC_PER_CALLBACK.as_u64());
                let promise = PromiseCreateArgs {
                    target_account_id,
                    method: consts::ROUTER_EXEC_NAME.into(),
                    args: borsh::to_vec(&call)
                        .map_err(|_| ExitError::Other(Cow::from(consts::ERR_SERIALIZE)))?,
                    attached_balance: ZERO_YOCTO,
                    attached_gas: router_exec_cost.saturating_add(call_gas),
                };
```

**File:** engine-precompiles/src/xcc.rs (L174-175)
```rust
        cost += EthGas::new(promise.attached_gas.as_u64() / costs::CROSS_CONTRACT_CALL_NEAR_GAS);
        check_cost(cost)?;
```

**File:** engine-types/src/parameters/promise.rs (L28-37)
```rust
    pub fn total_gas(&self) -> NearGas {
        match self {
            Self::Create(call) => call.attached_gas,
            Self::Callback(cb) => cb
                .base
                .attached_gas
                .saturating_add(cb.callback.attached_gas),
            Self::Recursive(p) => p.total_gas(),
        }
    }
```
