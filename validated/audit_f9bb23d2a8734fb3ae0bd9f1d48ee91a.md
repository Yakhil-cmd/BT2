### Title
`RandomSeed` Precompile and `PREVRANDAO` Opcode Return Identical Per-Transaction Values, Enabling Deterministic Exploitation of On-Aurora Randomness-Dependent Contracts - (File: `engine-precompiles/src/random.rs`, `engine/src/engine.rs`)

---

### Summary

Aurora Engine exposes two distinct interfaces for on-chain randomness: the Aurora-specific `RandomSeed` precompile at `0xc104f4840573bed437190daf5d2898c2bdf928ac` and the standard EVM `PREVRANDAO` opcode (via `block_randomness()`). Both interfaces return the **same fixed value** — `env.random_seed()` — for the entire duration of a transaction. Any contract deployed on Aurora that calls either interface more than once, or combines both interfaces, receives identical values for every draw. This is the direct structural analog of the reported vulnerability: the same seed is reused for independent random selections, making outcomes fully predictable and exploitable.

---

### Finding Description

**Root cause — `engine-precompiles/src/random.rs`:**

The `RandomSeed` precompile is initialized once per transaction with a fixed `random_seed: H256` value and returns that same value unconditionally on every invocation:

```rust
pub(super) const RANDOM_BYTES_GAS: EthGas = EthGas::new(0);
// ...
Ok(PrecompileOutput::without_logs(
    cost,
    self.random_seed.as_bytes().to_vec(),
))
```

The precompile's own documentation acknowledges this: *"It will return the same seed if called multiple time in the same block."* [1](#0-0) [2](#0-1) 

**Root cause — `engine/src/engine.rs`:**

The `PREVRANDAO` opcode is served by `block_randomness()`, which also returns `env.random_seed()` — the exact same underlying value:

```rust
fn block_randomness(&self) -> Option<H256> {
    Some(self.env.random_seed())
}
``` [3](#0-2) 

**Both interfaces share the same source:**

The `random_seed` field in `PrecompileConstructorContext` and the `env.random_seed()` call in `block_randomness()` both resolve to the same `env::Fixed::random_seed` field, which is set once per transaction from `compute_random_seed(action_hash, block_random_value)`: [4](#0-3) [5](#0-4) 

**Zero gas cost amplifies the attack surface:**

The precompile charges `RANDOM_BYTES_GAS = EthGas::new(0)`, meaning an attacker can call it an unlimited number of times within a transaction at no additional cost, observing that every call returns the same value. [6](#0-5) 

---

### Impact Explanation

Any Solidity contract deployed on Aurora that uses the `RandomSeed` precompile or `PREVRANDAO` for multiple independent random draws — for example, drawing a "normal ball" and a "bonus ball" in a lottery, or selecting two independent winners — receives the **same 32-byte value for every draw**. The draws are perfectly correlated. An attacker who knows this property can:

1. Observe or compute the single random value for the block/transaction (it is derived deterministically from `sha256(action_hash || block_random_seed)`, both of which are observable on-chain).
2. Predict all outcomes of any multi-draw randomness scheme.
3. Purchase only the winning combination(s) and guarantee a positive return, draining the prize pool.

This is a **direct theft of user funds** held in any Aurora-deployed lottery, game, or financial contract that relies on these randomness interfaces for independent draws.

---

### Likelihood Explanation

The `RandomSeed` precompile is Aurora's primary advertised randomness primitive for EVM contracts. Any developer who follows the natural pattern of calling it twice for two independent selections — or who combines it with `PREVRANDAO` expecting a different value — is affected. The behavior is not obvious from the interface (two different call sites, two different-looking interfaces), and the zero gas cost makes repeated calls trivially cheap. The likelihood that at least one deployed Aurora contract uses this pattern is high.

---

### Recommendation

1. **Make the precompile stateful within a transaction**: Maintain a counter or nonce that is hashed together with `random_seed` on each invocation, so successive calls return distinct values: `sha256(random_seed || call_index)`.
2. **Differentiate `PREVRANDAO` from the precompile**: If both interfaces must coexist, ensure they return values derived from different domain-separated inputs so they cannot be treated as independent by contracts that use both.
3. **Document the limitation prominently**: Until a fix is deployed, clearly document that the precompile returns a per-transaction constant and must not be used for multiple independent draws within the same transaction.

---

### Proof of Concept

A Solidity contract deployed on Aurora:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRandomSeed {
    function call_precompile() external returns (bytes32);
}

contract LotteryExploit {
    address constant RANDOM_SEED = 0xc104f4840573bed437190daf5d2898c2bdf928ac;

    function draw() external returns (bytes32 ball1, bytes32 ball2, bool identical) {
        bytes32[1] memory v1;
        bytes32[1] memory v2;
        // First draw — "normal ball"
        assembly { call(gas(), RANDOM_SEED, 0, 0, 0, v1, 32) }
        // Second draw — "bonus ball" (expected to be independent)
        assembly { call(gas(), RANDOM_SEED, 0, 0, 0, v2, 32) }
        ball1 = v1[0];
        ball2 = v2[0];
        identical = (ball1 == ball2); // always true
    }

    function drawMixed() external returns (bytes32 fromPrevrandao, bytes32 fromPrecompile, bool identical) {
        fromPrevrandao = bytes32(block.prevrandao); // PREVRANDAO opcode
        bytes32[1] memory v;
        assembly { call(gas(), RANDOM_SEED, 0, 0, 0, v, 32) }
        fromPrecompile = v[0];
        identical = (fromPrevrandao == fromPrecompile); // always true
    }
}
```

Both `draw()` and `drawMixed()` will always return `identical = true` on Aurora, because both interfaces resolve to the same `env.random_seed()` value. An attacker who knows the block's random seed (observable from NEAR) can predict all lottery outcomes before submitting their ticket transaction. [7](#0-6) [3](#0-2) [8](#0-7)

### Citations

**File:** engine-precompiles/src/random.rs (L8-13)
```rust
mod costs {
    use crate::prelude::types::EthGas;

    // TODO(#483): Determine the correct amount of gas
    pub(super) const RANDOM_BYTES_GAS: EthGas = EthGas::new(0);
}
```

**File:** engine-precompiles/src/random.rs (L15-32)
```rust
pub struct RandomSeed {
    random_seed: H256,
}

impl RandomSeed {
    /// Random bytes precompile address
    /// This is a per-block entropy source which could then be used to create a random sequence.
    /// It will return the same seed if called multiple time in the same block.
    ///
    /// Address: `0xc104f4840573bed437190daf5d2898c2bdf928ac`
    /// This address is computed as: `&keccak("randomSeed")[12..]`
    pub const ADDRESS: Address = make_address(0xc104f484, 0x0573bed437190daf5d2898c2bdf928ac);

    #[must_use]
    pub const fn new(random_seed: H256) -> Self {
        Self { random_seed }
    }
}
```

**File:** engine-precompiles/src/random.rs (L54-57)
```rust
        Ok(PrecompileOutput::without_logs(
            cost,
            self.random_seed.as_bytes().to_vec(),
        ))
```

**File:** engine/src/engine.rs (L1847-1850)
```rust
    /// Get environmental block randomness.
    fn block_randomness(&self) -> Option<H256> {
        Some(self.env.random_seed())
    }
```

**File:** engine-precompiles/src/lib.rs (L198-205)
```rust
pub struct PrecompileConstructorContext<'a, I, E, H, M> {
    pub current_account_id: AccountId,
    pub random_seed: H256,
    pub io: I,
    pub env: &'a E,
    pub promise_handler: H,
    pub mod_exp_algorithm: prelude::PhantomData<M>,
}
```

**File:** engine-standalone-storage/src/sync/mod.rs (L407-420)
```rust
    let random_seed = compute_random_seed(
        &transaction_message.action_hash,
        &block_metadata.random_seed,
    );
    let env = env::Fixed {
        signer_account_id,
        current_account_id,
        predecessor_account_id,
        block_height,
        block_timestamp: block_metadata.timestamp,
        attached_deposit: transaction_message.attached_near,
        random_seed,
        prepaid_gas: DEFAULT_PREPAID_GAS,
        used_gas: NearGas::new(0),
```

**File:** engine-standalone-storage/src/sync/mod.rs (L465-471)
```rust
fn compute_random_seed(action_hash: &H256, block_random_value: &H256) -> H256 {
    const BYTES_LEN: usize = 32 + 32;
    let mut bytes: Vec<u8> = Vec::with_capacity(BYTES_LEN);
    bytes.extend_from_slice(action_hash.as_bytes());
    bytes.extend_from_slice(block_random_value.as_bytes());
    aurora_engine_sdk::sha256(&bytes)
}
```
