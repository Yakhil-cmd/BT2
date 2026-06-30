### Title
Unbounded Recursive Stack Exhaustion in `NearPromise` Deserialization and Traversal via XCC Precompile - (File: `engine-types/src/parameters/promise.rs`, `etc/xcc-router/src/lib.rs`)

### Summary

The `NearPromise` type is a recursive enum with no depth limit. Its hand-written `BorshDeserialize` implementation calls itself recursively without bound, and `Router::recursive_promise_create` traverses it with unbounded recursion. An EVM user can craft a deeply nested `NearPromise::Then { base: Box<NearPromise::Then { ... }> }` payload and submit it via the XCC precompile (`CrossContractCallArgs::Eager` or `Delayed`). During deserialization inside the Aurora Engine WASM contract, or during traversal inside the XCC router contract, the Wasm stack overflows, causing the NEAR transaction to panic and abort. When used with `Delayed`, the malicious promise is stored in the router's `scheduled_promises` map and can never be executed, permanently freezing any wNEAR funds that were transferred as part of the XCC call.

### Finding Description

**Root cause — unbounded recursive deserialization:**

`NearPromise` is a recursive type. Its `BorshDeserialize` implementation is written by hand and recurses without any depth guard:

```rust
// engine-types/src/parameters/promise.rs, line 191
0x01 => {
    let base = Self::deserialize_reader(reader)?;  // <-- unbounded recursion
    ...
}
``` [1](#0-0) 

A crafted Borsh payload consisting of N consecutive `0x01` bytes (each representing `NearPromise::Then`) followed by a valid leaf causes `deserialize_reader` to recurse N frames deep on the Wasm call stack before returning.

**Root cause — unbounded recursive traversal:**

`Router::recursive_promise_create` in the XCC router contract also recurses without bound over the same structure:

```rust
// etc/xcc-router/src/lib.rs, line 253-254
NearPromise::Then { base, callback } => {
    let base_index = Self::recursive_promise_create(base);  // <-- unbounded recursion
``` [2](#0-1) 

**Entry path:**

1. An unprivileged EVM user calls the XCC precompile at `0x516cded1d16af10cad47d6d49128e2eb7d27b372` with a `CrossContractCallArgs::Delayed(PromiseArgs::Recursive(deeply_nested_NearPromise))` payload. [3](#0-2) 

2. The precompile deserializes the input via `CrossContractCallArgs::try_from_slice(input)`, which calls `NearPromise::deserialize_reader` recursively — stack overflow here aborts the Aurora Engine WASM execution. [4](#0-3) 

3. If the nesting is moderate enough to survive deserialization but deep enough to exhaust the router's stack, the serialized promise is stored in `scheduled_promises` via `Router::schedule`. The attacker can attach wNEAR (required for the XCC call) which is transferred before the promise is stored. [5](#0-4) 

4. When `execute_scheduled` is later called (by anyone, since it is intentionally open), `Router::recursive_promise_create` recurses over the stored `NearPromise` and overflows the Wasm stack, causing the call to panic. The promise entry is removed from `scheduled_promises` at the start of `execute_scheduled` before the overflow occurs, so the promise is gone but the attached wNEAR is not refunded. [6](#0-5) 

**No depth limit exists anywhere in the pipeline.** The `promise_count()` and `total_gas()` methods on `NearPromise` also recurse without bound, meaning even the gas-accounting traversal done in the `Eager` path can overflow. [7](#0-6) 

### Impact Explanation

**Permanent freezing of funds (High).**

In the `Delayed` path: the attacker pays wNEAR into the XCC system (required by the precompile when no router exists yet, `STORAGE_AMOUNT = 2 NEAR`), the promise is stored, and every subsequent `execute_scheduled` call overflows and panics. The stored promise is deleted at the top of `execute_scheduled` before the overflow, so it cannot be retried. The 2 NEAR (or any attached wNEAR balance) locked in the router sub-account is permanently inaccessible.

In the `Eager` path: the overflow occurs during deserialization or gas accounting inside the Aurora Engine WASM call itself, causing the entire EVM transaction to abort. This is a self-harm DoS (the attacker's own gas is wasted) but can also be used to grief the relayer or block specific contract interactions.

### Likelihood Explanation

The XCC precompile is a standard production feature reachable by any EVM user with an Aurora account. Crafting a deeply nested Borsh-encoded `NearPromise` requires only knowledge of the Borsh encoding format (public) and the `NearPromise` variant byte layout (public, documented in source). No privileged access is required. The minimum cost is the wNEAR storage deposit (~2 NEAR) plus EVM gas. This is a realistic, low-cost attack.

### Recommendation

1. **Add a depth limit to `NearPromise::deserialize_reader`**: Track recursion depth and return an `io::Error` if it exceeds a safe threshold (e.g., 64).
2. **Add a depth limit to `Router::recursive_promise_create`**: Pass a depth counter and panic/return an error if exceeded.
3. **Validate promise depth in the XCC precompile** before serializing and forwarding the promise to the router, so malformed inputs are rejected at the EVM layer with an `OutOfGas` or revert rather than causing a Wasm stack overflow.
4. **In `execute_scheduled`**: remove the promise from storage only after successful execution, or implement a try/catch equivalent so that a failed execution does not destroy the stored promise without refunding attached funds.

### Proof of Concept

Construct the following Borsh payload for `CrossContractCallArgs::Delayed(PromiseArgs::Recursive(NearPromise))`:

```
// CrossContractCallArgs variant byte: 0x01 (Delayed)
// PromiseArgs variant byte: 0x02 (Recursive)
// NearPromise: 10000 nested Then nodes
// Each Then node: 0x01 || <recursive base> || <SimpleNearPromise leaf>
// Leaf: 0x00 || <PromiseCreateArgs with minimal valid fields>

payload = b"\x01"          # CrossContractCallArgs::Delayed
        + b"\x02"          # PromiseArgs::Recursive
        + b"\x01" * 10000  # 10000 NearPromise::Then wrappers (each recurses)
        + b"\x00"          # NearPromise::Simple leaf
        + <valid PromiseCreateArgs borsh bytes>
```

Submit this as the calldata of an EVM transaction targeting the XCC precompile address `0x516cded1d16af10cad47d6d49128e2eb7d27b372`. The Aurora Engine WASM runtime will overflow its call stack during `NearPromise::deserialize_reader` at: [8](#0-7) 

For the router-side overflow: use a nesting depth that survives deserialization (e.g., 1000 levels) but overflows `recursive_promise_create` at: [9](#0-8)

### Citations

**File:** engine-types/src/parameters/promise.rs (L116-122)
```rust
    pub fn promise_count(&self) -> u64 {
        match self {
            Self::Simple(_) => 1,
            Self::Then { base, .. } => base.promise_count() + 1,
            Self::And(ps) => ps.iter().map(Self::promise_count).sum(),
        }
    }
```

**File:** engine-types/src/parameters/promise.rs (L178-207)
```rust
impl BorshDeserialize for NearPromise {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let variant_byte = {
            let mut buf = [0u8; 1];
            reader.read_exact(&mut buf)?;
            buf[0]
        };
        match variant_byte {
            0x00 => {
                let inner = SimpleNearPromise::deserialize_reader(reader)?;
                Ok(Self::Simple(inner))
            }
            0x01 => {
                let base = Self::deserialize_reader(reader)?;
                let callback = SimpleNearPromise::deserialize_reader(reader)?;
                Ok(Self::Then {
                    base: Box::new(base),
                    callback,
                })
            }
            0x02 => {
                let promises: Vec<Self> = Vec::deserialize_reader(reader)?;
                Ok(Self::And(promises))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid variant byte for NearPromise",
            )),
        }
    }
```

**File:** etc/xcc-router/src/lib.rs (L136-144)
```rust
    pub fn schedule(&mut self, #[serializer(borsh)] promise: PromiseArgs) {
        self.assert_preconditions();

        let nonce = self.nonce.get().unwrap_or_default();
        self.scheduled_promises.insert(nonce, promise);
        self.nonce.set(&(nonce + 1));

        near_sdk::log!("Promise scheduled at nonce {}", nonce);
    }
```

**File:** etc/xcc-router/src/lib.rs (L150-156)
```rust
    pub fn execute_scheduled(&mut self, nonce: U64) {
        let Some(promise) = self.scheduled_promises.remove(&nonce.0) else {
            env::panic_str("ERR_PROMISE_NOT_FOUND")
        };
        let promise_id = Self::promise_create(promise);
        env::promise_return(promise_id);
    }
```

**File:** etc/xcc-router/src/lib.rs (L242-282)
```rust
    fn recursive_promise_create(promise: &NearPromise) -> PromiseIndex {
        match promise {
            NearPromise::Simple(x) => match x {
                SimpleNearPromise::Create(call) => Self::base_promise_create(call),
                SimpleNearPromise::Batch(batch) => {
                    let target = batch.target_account_id.as_ref().parse().unwrap();
                    let id = env::promise_batch_create(&target);
                    Self::add_batch_actions(id, &batch.actions);
                    id
                }
            },
            NearPromise::Then { base, callback } => {
                let base_index = Self::recursive_promise_create(base);
                match callback {
                    SimpleNearPromise::Create(call) => env::promise_then(
                        base_index,
                        call.target_account_id.as_ref().parse().unwrap(),
                        call.method.as_str(),
                        &call.args,
                        NearToken::from_yoctonear(call.attached_balance.as_u128()),
                        Gas::from_gas(call.attached_gas.as_u64()),
                    ),
                    SimpleNearPromise::Batch(batch) => {
                        let id = env::promise_batch_then(
                            base_index,
                            &batch.target_account_id.as_ref().parse().unwrap(),
                        );
                        Self::add_batch_actions(id, &batch.actions);
                        id
                    }
                }
            }
            NearPromise::And(promises) => {
                let indices: Vec<PromiseIndex> = promises
                    .iter()
                    .map(Self::recursive_promise_create)
                    .collect();
                env::promise_and(&indices)
            }
        }
    }
```

**File:** engine-precompiles/src/xcc.rs (L137-172)
```rust
        let args = CrossContractCallArgs::try_from_slice(input)
            .map_err(|_| ExitError::Other(Cow::from(consts::ERR_INVALID_INPUT)))?;
        let (promise, attached_near) = match args {
            CrossContractCallArgs::Eager(call) => {
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
                (promise, attached_near)
            }
            CrossContractCallArgs::Delayed(call) => {
                let attached_near = call.total_near();
                let promise = PromiseCreateArgs {
                    target_account_id,
                    method: consts::ROUTER_SCHEDULE_NAME.into(),
                    args: borsh::to_vec(&call)
                        .map_err(|_| ExitError::Other(Cow::from(consts::ERR_SERIALIZE)))?,
                    attached_balance: ZERO_YOCTO,
                    // We don't need to add any gas to the amount need for the schedule call
                    // since the promise is not executed right away.
                    attached_gas: costs::ROUTER_SCHEDULE,
                };
                (promise, attached_near)
            }
```
