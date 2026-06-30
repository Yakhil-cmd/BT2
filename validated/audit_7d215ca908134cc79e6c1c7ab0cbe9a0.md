### Title
Unbounded `move_to_block` Loop in Hashchain Causes NEAR Gas Exhaustion on Every User Transaction After Engine Inactivity - (`engine-hashchain/src/hashchain.rs`)

### Summary

The `Hashchain::move_to_block` function contains an unbounded `while` loop that iterates once per NEAR block skipped since the last Aurora Engine transaction. This function is invoked on every user-facing call (`submit`, `call`, `ft_on_transfer`, etc.) via `load_hashchain`. When the engine has been idle for a sufficient number of blocks, the loop exhausts the NEAR gas limit, causing all user transactions to fail. Because a failed NEAR transaction reverts state, the hashchain is never updated, making the DoS self-reinforcing until admin intervention.

---

### Finding Description

**Root cause — `move_to_block` in `engine-hashchain/src/hashchain.rs`:** [1](#0-0) 

The loop `while self.current_block_height < next_block_height` iterates `(current_block_height - stored_block_height)` times. Each iteration calls `compute_block_hashchain` (one keccak256 hash) and `clear_txs` (resets a 256-byte bloom filter and a Merkle tree). The iteration count is unbounded and grows linearly with the number of NEAR blocks elapsed since the last Aurora transaction.

**Hot-path call chain — `engine/src/hashchain.rs`:**

`load_hashchain` is called by both `with_hashchain` and `with_logs_hashchain`: [2](#0-1) 

`with_logs_hashchain` wraps every `submit` and `call`: [3](#0-2) 

`with_hashchain` wraps `ft_on_transfer`, `register_relayer`, and other state-mutating methods: [4](#0-3) 

**Entry points exposed to unprivileged callers:** [5](#0-4) [6](#0-5) 

**Self-reinforcing DoS:** Because NEAR reverts state on out-of-gas, the hashchain's `current_block_height` is never advanced on a failed transaction. Every subsequent transaction faces the same (or larger) gap, making the DoS permanent until an admin pauses the engine and calls `start_hashchain`.

**Recovery path requires engine pause:** `start_hashchain` requires `require_paused`, meaning the engine must be halted before the hashchain can be reset: [7](#0-6) 

---

### Impact Explanation

When the hashchain feature is active and the Aurora Engine has been idle for N NEAR blocks, the first user transaction after that idle period must execute `move_to_block` with N iterations before any EVM logic runs. Each iteration performs at least one keccak256 hash plus memory operations. NEAR's per-transaction gas limit is 300 Tgas. Once N is large enough to exhaust this budget (accounting for the gas already consumed by EVM execution, storage I/O, and hashchain serialization), every user transaction — `submit`, `call`, `ft_on_transfer` — fails with out-of-gas. Funds bridged to Aurora become inaccessible. The state is never updated on failure, so the condition is permanent until admin intervention (pause → `start_hashchain` → unpause), during which the engine is also unavailable.

**Impact class:** High — Temporary (potentially extended) freezing of funds.

---

### Likelihood Explanation

- The hashchain is an opt-in feature initialized by an admin via `start_hashchain` or the `new` constructor with `initial_hashchain`. Once enabled, it is active on every user transaction.
- NEAR produces approximately one block per second. A gap of a few hundred to a few thousand idle blocks (minutes to hours of low activity) is sufficient to push the loop cost past the available gas budget, depending on the EVM workload sharing the same transaction gas.
- No attacker action is required beyond submitting a normal transaction after a natural idle period. Any user who happens to be first after inactivity triggers the failure.
- The self-reinforcing nature means a single idle period can permanently disable the engine without admin recovery.

---

### Recommendation

Replace the per-block iteration with a single-step computation. The hashchain does not need to hash every empty intermediate block individually; it can compute the cumulative hash for a range of empty blocks in O(1) by treating consecutive empty blocks as a deterministic sequence. Alternatively:

1. Store only the last-seen block height and compute the "fast-forward" hash mathematically without looping.
2. Cap the number of iterations in `move_to_block` and return an error (or a partial result) if the gap exceeds a safe threshold, allowing the admin to call `start_hashchain` proactively.
3. Move the hashchain update to a separate, dedicated NEAR call that is not bundled with user EVM execution, so gas exhaustion in the hashchain path does not block user transactions.

---

### Proof of Concept

1. Admin initializes the Aurora Engine with hashchain enabled (`start_hashchain` at block height H).
2. The engine receives no transactions for N blocks (N large enough to exhaust gas; e.g., a few hundred blocks at ~1 s/block).
3. An unprivileged user submits any transaction (e.g., a simple ETH transfer via `submit`).
4. `with_logs_hashchain` → `load_hashchain` → `move_to_block(H + N)` executes N iterations of `compute_block_hashchain` + `clear_txs`.
5. The NEAR transaction runs out of gas; state is reverted; the hashchain remains at height H.
6. Every subsequent user transaction repeats steps 3–5 with an equal or larger gap, permanently blocking all user interactions until an admin pauses the engine and resets the hashchain via `start_hashchain`. [8](#0-7)

### Citations

**File:** engine-hashchain/src/hashchain.rs (L67-88)
```rust
    pub fn move_to_block(
        &mut self,
        next_block_height: u64,
    ) -> Result<(), BlockchainHashchainError> {
        if next_block_height <= self.current_block_height {
            return Err(BlockchainHashchainError::BlockHeightIncorrect);
        }

        while self.current_block_height < next_block_height {
            self.previous_block_hashchain = self.block_hashchain_computer.compute_block_hashchain(
                &self.chain_id,
                self.contract_account_id.as_bytes(),
                self.current_block_height,
                self.previous_block_hashchain,
            );

            self.block_hashchain_computer.clear_txs();
            self.current_block_height += 1;
        }

        Ok(())
    }
```

**File:** engine/src/hashchain.rs (L21-52)
```rust
pub fn with_hashchain<I, E, T, F>(
    mut io: I,
    env: &E,
    function_name: &str,
    f: F,
) -> Result<T, ContractError>
where
    I: IO + Copy,
    E: Env,
    F: for<'a> FnOnce(CachedIO<'a, I>) -> Result<T, ContractError>,
{
    let block_height = env.block_height();
    let maybe_hashchain = load_hashchain(&io, block_height)?;

    let cache = RefCell::new(IOCache::default());
    let hashchain_io = CachedIO::new(io, &cache);
    let result = f(hashchain_io)?;

    if let Some(mut hashchain) = maybe_hashchain {
        let cache_ref = cache.borrow();
        hashchain.add_block_tx(
            block_height,
            function_name,
            &cache_ref.input,
            &cache_ref.output,
            &Bloom::default(),
        )?;
        save_hashchain(&mut io, &hashchain)?;
    }

    Ok(result)
}
```

**File:** engine/src/hashchain.rs (L54-86)
```rust
pub fn with_logs_hashchain<I, E, F>(
    mut io: I,
    env: &E,
    function_name: &str,
    f: F,
) -> Result<SubmitResult, ContractError>
where
    I: IO + Copy,
    E: Env,
    F: for<'a> FnOnce(CachedIO<'a, I>) -> Result<SubmitResult, ContractError>,
{
    let block_height = env.block_height();
    let maybe_hashchain = load_hashchain(&io, block_height)?;

    let cache = RefCell::new(IOCache::default());
    let hashchain_io = CachedIO::new(io, &cache);
    let result = f(hashchain_io)?;

    if let Some(mut hashchain) = maybe_hashchain {
        let log_bloom = bloom::get_logs_bloom(&result.logs);
        let cache_ref = cache.borrow();
        hashchain.add_block_tx(
            block_height,
            function_name,
            &cache_ref.input,
            &cache_ref.output,
            &log_bloom,
        )?;
        save_hashchain(&mut io, &hashchain)?;
    }

    Ok(result)
}
```

**File:** engine/src/hashchain.rs (L88-96)
```rust
fn load_hashchain<I: IO>(io: &I, block_height: u64) -> Result<Option<Hashchain>, ContractError> {
    let mut maybe_hashchain = read_current_hashchain(io)?;
    if let Some(hashchain) = maybe_hashchain.as_mut()
        && block_height > hashchain.get_current_block_height()
    {
        hashchain.move_to_block(block_height)?;
    }
    Ok(maybe_hashchain)
}
```

**File:** engine/src/lib.rs (L275-282)
```rust
    pub extern "C" fn submit() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::evm_transactions::submit(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine/src/contract_methods/connector.rs (L61-109)
```rust
#[named]
pub fn ft_on_transfer<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<Option<SubmitResult>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let current_account_id = env.current_account_id();
        let predecessor_account_id = env.predecessor_account_id();
        let mut engine: Engine<_, _> = Engine::new(
            predecessor_address(&predecessor_account_id),
            current_account_id.clone(),
            io,
            env,
        )?;

        sdk::log!("Call ft_on_transfer");

        let args: FtOnTransferArgs = read_json_args(&io)?;
        let result = if predecessor_account_id == get_connector_account_id(&io)? {
            engine.receive_base_tokens(&args)
        } else {
            engine.receive_erc20_tokens(
                &predecessor_account_id,
                &args,
                &current_account_id,
                handler,
            )
        };

        #[allow(clippy::used_underscore_binding)]
        let amount_to_return = if let Err(_err) = &result {
            sdk::log!("Error in ft_on_transfer: {_err:?}");
            // An error occurred, so we need to return the amount of tokens to the sender.
            args.amount.as_u128()
        } else {
            // Everything is ok, so return 0.
            0
        };

        let output = crate::prelude::format!("\"{amount_to_return}\"");
        io.return_output(output.as_bytes());

        // In case of an error, we just return Ok(None) to avoid a panic in the contract. It's ok
        // because in case of an error, we already returned the amount of tokens to the sender.
        Ok(result.unwrap_or(None))
    })
}
```

**File:** engine/src/contract_methods/admin.rs (L426-464)
```rust
pub fn start_hashchain<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    let mut state = state::get_state(&io)?;
    require_paused(&state)?;
    require_key_manager_only(&state, &env.predecessor_account_id())?;

    let input = io.read_input().to_vec();
    let args = StartHashchainArgs::try_from_slice(&input).map_err(|_| errors::ERR_SERIALIZE)?;
    let block_height = env.block_height();

    // Starting hashchain must be for an earlier block
    if block_height < args.block_height {
        return Err(errors::ERR_ARGS.into());
    }

    let mut hashchain = Hashchain::new(
        state.chain_id,
        env.current_account_id(),
        args.block_height + 1,
        args.block_hashchain,
    );

    if hashchain.get_current_block_height() < block_height {
        hashchain.move_to_block(block_height)?;
    }

    hashchain.add_block_tx(
        block_height,
        function_name!(),
        &input,
        &[],
        &Bloom::default(),
    )?;
    crate::hashchain::save_hashchain(&mut io, &hashchain)?;

    state.is_paused = false;
    state::set_state(&mut io, &state)?;

    Ok(())
}
```
