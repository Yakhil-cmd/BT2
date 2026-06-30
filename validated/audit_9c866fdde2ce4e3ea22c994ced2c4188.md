### Title
Unbounded Loop in `move_to_block` Can Temporarily Freeze All Engine Transactions - (`engine-hashchain/src/hashchain.rs`)

### Summary
The `move_to_block` function in the hashchain module contains an unbounded `while` loop that iterates once per NEAR block from the last stored hashchain height to the current block height. This function is invoked on every mutative engine call via `load_hashchain`. If the engine is idle for a sufficient number of NEAR blocks, the loop will exhaust the 300 Tgas NEAR transaction gas limit, causing every subsequent user transaction to fail until admin intervention.

### Finding Description

`move_to_block` in `engine-hashchain/src/hashchain.rs` contains an unbounded `while` loop:

```rust
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
``` [1](#0-0) 

The number of iterations equals `current_block_height - stored_hashchain_height`, i.e., the number of NEAR blocks that have elapsed since the last hashchain update. Each iteration invokes `compute_block_hashchain`, which performs a keccak hash, and `clear_txs`.

This function is called unconditionally from `load_hashchain`:

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
``` [2](#0-1) 

`load_hashchain` is called at the start of both `with_hashchain` and `with_logs_hashchain`, which wrap every mutative contract method (e.g., `submit`, `ft_on_transfer`, `deploy_erc20_token`, `ft_transfer`, etc.): [3](#0-2) 

The hashchain state is only saved **after** the loop completes successfully. If the loop exhausts gas (a WASM trap, not a Rust error), the state is never updated, so every subsequent call re-enters the same oversized loop and fails identically.

### Impact Explanation

When the hashchain is active and the engine is idle for enough NEAR blocks, the first user transaction triggers `move_to_block` with a gap too large to complete within 300 Tgas. The transaction fails. Because the hashchain state is never written, every subsequent transaction also fails. All engine functionality — ETH withdrawals, ERC-20 transfers, XCC calls, and any other `with_hashchain`-wrapped method — is frozen until an admin pauses the engine and re-initializes the hashchain via `start_hashchain`.

**Impact**: High — Temporary freezing of funds (all user assets locked in the engine until admin recovery).

### Likelihood Explanation

NEAR produces blocks approximately every 1 second. Each iteration of `move_to_block` performs at least one keccak256 hash. The NEAR `keccak256` host function costs approximately 1.5–3 Tgas. With a 300 Tgas limit, the loop can safely process roughly 100–200 blocks before exhausting gas. This corresponds to only **1.5–3 minutes of engine idle time**. Any period of low activity — routine maintenance, a temporary pause, or simply low user demand — can trigger this condition. The engine does not need to be paused; the hashchain simply needs to fall behind the current block height by a sufficient margin.

### Recommendation

Replace the unbounded `while` loop in `move_to_block` with a design that does not require iterating through every missed block. Options include:

1. **Lazy/sparse hashchain**: Only record the current block's hash without iterating through all skipped blocks. Empty blocks can be represented by a single hash of the previous hashchain and the block height, computed in O(1).
2. **Bounded catch-up**: Cap the number of iterations per call (e.g., process at most N blocks per transaction), and allow the hashchain to catch up over multiple transactions.
3. **Skip-block hashing**: Compute a single aggregate hash for a range of empty blocks rather than iterating one-by-one.

### Proof of Concept

1. Admin calls `start_hashchain` at NEAR block height N, initializing the hashchain. [4](#0-3) 

2. The engine receives no transactions for M blocks (M ≈ 150–200, i.e., ~2–3 minutes of idle time).

3. An unprivileged user submits any transaction (e.g., `submit`, `ft_transfer`, `ft_on_transfer`).

4. The call enters `with_hashchain` → `load_hashchain` → `move_to_block(N + M)`. [5](#0-4) 

5. The `while` loop in `move_to_block` iterates M times, each computing a keccak hash. After ~150–200 iterations the NEAR 300 Tgas limit is exhausted; the WASM execution traps.

6. The transaction fails. The hashchain state is not updated (the `save_hashchain` call is never reached).

7. Every subsequent user transaction re-enters the same loop at the same stored height and fails identically. All engine functionality is frozen until an admin pauses the engine and calls `start_hashchain` with a recent block height. [6](#0-5)

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

**File:** engine/src/contract_methods/admin.rs (L426-463)
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
```
